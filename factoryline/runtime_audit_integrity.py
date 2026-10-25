"""Runtime evidence joins, callback reconciliation, and advisory repair routing."""

import ast
import copy
import hashlib
import re
from collections import Counter
from typing import Any
from pathlib import Path

from .runtime_audit_common import RuntimeAuditError
from .runtime_audit_contract import LANES
from . import finite_capture as _finite_capture
from .finite_capture import (
    _fixed_program_span as _fixed_program_span,
    _fixed_eval_name_hazard as _fixed_eval_name_hazard,
    _fixed_eval_import_hazard as _fixed_eval_import_hazard,
    _fixed_eval_attribute_hazard as _fixed_eval_attribute_hazard,
    _fixed_eval_builtin_source_clear as _fixed_eval_builtin_source_clear,
    _fixed_eval_builtin_aliases as _fixed_eval_builtin_aliases,
    _fixed_eval_provider_root as _fixed_eval_provider_root,
    _fixed_eval_provider_capability as _fixed_eval_provider_capability,
    _fixed_eval_provider_alias_escape as _fixed_eval_provider_alias_escape,
    _fixed_eval_builtin_write as _fixed_eval_builtin_write,
    _fixed_eval_builtin_subscript as _fixed_eval_builtin_subscript,
    _fixed_eval_builtin_reflection as _fixed_eval_builtin_reflection,
    _fixed_eval_dynamic_import_risk as _fixed_eval_dynamic_import_risk,
    _fixed_eval_module_alias_escape as _fixed_eval_module_alias_escape,
    _fixed_eval_module_scope as _fixed_eval_module_scope,
    _fixed_eval_interpreter_aliases as _fixed_eval_interpreter_aliases,
    _fixed_eval_interpreter_call as _fixed_eval_interpreter_call,
    _fixed_eval_callable_reaches_risk as _fixed_eval_callable_reaches_risk,
    _fixed_eval_class_init_hooks as _fixed_eval_class_init_hooks,
    _fixed_eval_local_class_aliases as _fixed_eval_local_class_aliases,
    _fixed_eval_local_function_risks as _fixed_eval_local_function_risks,
    _fixed_eval_local_class_risks as _fixed_eval_local_class_risks,
    _fixed_eval_module_init_constructor_call as _fixed_eval_module_init_constructor_call,
    _fixed_eval_module_init_risky_reference as _fixed_eval_module_init_risky_reference,
    _fixed_eval_interpreter_payload as _fixed_eval_interpreter_payload,
    _fixed_eval_nested_interpreter_risk as _fixed_eval_nested_interpreter_risk,
    _fixed_eval_local_init_call_risk as _fixed_eval_local_init_call_risk,
    _fixed_eval_builtin_provider_risk as _fixed_eval_builtin_provider_risk,
    fixed_eval_workspace_provider_clear as fixed_eval_workspace_provider_clear,
    _fixed_eval_sink_context as _fixed_eval_sink_context,
    _fixed_eval_control_flow as _fixed_eval_control_flow,
    _fixed_eval_sink_statement as _fixed_eval_sink_statement,
    _fixed_eval_parameters as _fixed_eval_parameters,
    _fixed_eval_external_state as _fixed_eval_external_state,
    _fixed_eval_row as _fixed_eval_row,
    _fixed_eval_is_bytes_decode as _fixed_eval_is_bytes_decode,
    _fixed_eval_decode_state as _fixed_eval_decode_state,
    _fixed_eval_assignment_state as _fixed_eval_assignment_state,
    _fixed_eval_local_states as _fixed_eval_local_states,
    _fixed_eval_definition_rows as _fixed_eval_definition_rows,
    _fixed_eval_proof as _fixed_eval_proof,
    fixed_eval_local_input_witness as fixed_eval_local_input_witness,
    _fixed_literal_program_kinds as _fixed_literal_program_kinds,
)
from .finite_capture import (
    _FiniteInputCapture,
    finite_template_capture_shape,
    finite_domain_reference_allowed,
    finite_provider_attribute_write_index,
    finite_blocked_provider_prefixes,
    finite_scope_binding_candidate,
    _finite_eval_comprehension,  # noqa: F401
    _finite_eval_domain,  # noqa: F401
    _finite_eval_module_prefix,  # noqa: F401
    _finite_template_program_hash,
    _fixed_literal_value as _fixed_literal_value,
    finite_literal_eval_input_witness,  # noqa: F401
    finite_template_program_hashes,
)
from .provenance import _LiteralConsumers as _LiteralConsumers

_FULL_REPOSITORY_WORKSPACE_PREFIX_CACHE = None


def _full_repository_workspace_store_prefix(
    checkpoint_key, result_digest, context_digest, rows, digest
):
    global _FULL_REPOSITORY_WORKSPACE_PREFIX_CACHE
    owned = copy.deepcopy(rows)
    _FULL_REPOSITORY_WORKSPACE_PREFIX_CACHE = (
        checkpoint_key,
        result_digest,
        context_digest,
        digest(owned),
        owned,
    )


def _full_repository_workspace_load_prefix(
    engine, generation, results, files, source_by_name, context_digest
):
    cached = _FULL_REPOSITORY_WORKSPACE_PREFIX_CACHE
    key = generation.get("workspace_prefix_cache_key")
    if (
        cached is None
        or key is None
        or cached[0] != key
        or cached[1] != engine.digest(results)
        or cached[1] != generation.get("saved_result_digest")
        or cached[2] != context_digest
        or cached[2] != generation.get("saved_context_generation_sha256")
        or cached[3] != engine.digest(cached[4])
        or len(cached[4]) != len(results)
    ):
        return None
    rows = copy.deepcopy(cached[4])
    for row, path, primary in zip(rows, files, results):
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "binding", "findings", "status"}
            or row["path"] != path.relative_to(generation["root"]).as_posix()
            or row["path"] != primary.get("path")
            or row["status"] != primary.get("status")
            or row["findings"] != primary.get("findings")
        ):
            return None
        source = source_by_name.get(row["path"])
        binding = row["binding"]
        if binding is not None and (
            not isinstance(binding, dict)
            or binding.get("sha256") != (source or {}).get("sha256")
        ):
            return None
    return rows


def _closed_declaration_program(node, call_name):
    if (
        call_name != "exec"
        or not isinstance(node, ast.Call)
        or not isinstance(node.func, ast.Name)
        or node.func.id != "exec"
        or len(node.args) != 3
        or node.keywords
        or not isinstance(node.args[0], ast.Constant)
        or type(node.args[0].value) is not str
        or not isinstance(node.args[1], ast.Name)
        or not isinstance(node.args[2], ast.Constant)
        or node.args[2].value is not None
    ):
        return None
    import keyword

    match = re.fullmatch(r"type ([A-Za-z][A-Za-z0-9_]*) = int", node.args[0].value)
    if not match or keyword.iskeyword(match[1]) or match[1] in {"type", "int"}:
        return None
    return match[1]


def _closed_declaration_namespace(tree, call, alias):
    scope = next(
        (
            fn
            for fn in ast.walk(tree)
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
            and any(isinstance(s, ast.Expr) and s.value is call for s in fn.body)
        ),
        None,
    )
    if scope is None:
        return False
    name = call.args[1].id
    assignments = [
        s
        for s in scope.body
        if isinstance(s, (ast.Assign, ast.AnnAssign))
        and isinstance(s.value, ast.Dict)
        and not s.value.keys
        and (
            (
                isinstance(s, ast.Assign)
                and len(s.targets) == 1
                and isinstance(s.targets[0], ast.Name)
                and s.targets[0].id == name
            )
            or (
                isinstance(s, ast.AnnAssign)
                and isinstance(s.target, ast.Name)
                and s.target.id == name
            )
        )
    ]
    if len(assignments) != 1 or assignments[0].lineno >= call.lineno:
        return False
    target = (
        assignments[0].targets[0]
        if isinstance(assignments[0], ast.Assign)
        else assignments[0].target
    )
    if any(
        name in _oracle_bound_names(s) for s in scope.body if s is not assignments[0]
    ):
        return False
    parents = {
        child: parent
        for parent in ast.walk(scope)
        for child in ast.iter_child_nodes(parent)
    }
    for item in ast.walk(scope):
        if isinstance(item, ast.arg) and item.arg == name:
            return False
        if isinstance(item, (ast.Global, ast.Nonlocal)) and name in item.names:
            return False
        if (
            not isinstance(item, ast.Name)
            or item.id != name
            or item is target
            or item is call.args[1]
        ):
            continue
        parent = parents.get(item)
        if not (
            item.lineno > call.lineno
            and isinstance(parent, ast.Subscript)
            and parent.value is item
            and isinstance(parent.ctx, ast.Load)
            and isinstance(parent.slice, ast.Constant)
            and parent.slice.value == alias
        ):
            return False
    return True


def _closed_declaration_binding(tree, call):
    """Reject explicit source rebinding; this does not attest external runtime state."""
    from .review_audits import _binding_name

    for item in ast.walk(tree):
        if item is call.func:
            continue
        if _binding_name(item) in {"exec", "int"}:
            return False
        if isinstance(item, (ast.Name, ast.arg)):
            name = item.id if isinstance(item, ast.Name) else item.arg
            if (
                name
                in {
                    "exec",
                    "eval",
                    "__builtins__",
                    "globals",
                    "locals",
                    "vars",
                    "setattr",
                    "delattr",
                }
                or name == "int"
                and (
                    isinstance(item, ast.arg)
                    or isinstance(item.ctx, (ast.Store, ast.Del))
                )
            ):
                return False
        if isinstance(
            item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ) and item.name in {"exec", "int"}:
            return False
        if isinstance(item, (ast.Import, ast.ImportFrom)) and any(
            (a.asname or a.name.split(".")[0]) in {"exec", "eval", "int"}
            or a.name == "*"
            for a in item.names
        ):
            return False
        if (
            isinstance(item, ast.ImportFrom)
            and item.module == "builtins"
            and any(
                a.name
                in {
                    "exec",
                    "eval",
                    "setattr",
                    "delattr",
                    "__dict__",
                    "__builtins__",
                    "globals",
                    "locals",
                    "vars",
                }
                for a in item.names
            )
        ):
            return False
        if isinstance(item, ast.Attribute) and (
            item.attr
            in {
                "exec",
                "eval",
                "__dict__",
                "__builtins__",
                "__setattr__",
                "__delattr__",
                "setattr",
                "delattr",
            }
            or item.attr == "int"
            and isinstance(item.ctx, (ast.Store, ast.Del))
        ):
            return False
    return True


def _source_span(node):
    return [
        getattr(node, key, None)
        for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ]


def _exact_source_call(source_bytes, node):
    """Return the source call only when its complete AST and span match."""
    try:
        tree = ast.parse(source_bytes)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return None
    matches = [
        item
        for item in ast.walk(tree)
        if isinstance(item, ast.Call) and _source_span(item) == _source_span(node)
    ]
    if len(matches) != 1 or ast.dump(matches[0]) != ast.dump(node):
        return None
    return tree, matches[0]


def _closed_declaration_source_call(node, call_name, source_bytes, source_path):
    """Validate source binding for a fixed declaration input witness."""
    if (
        not isinstance(source_bytes, bytes)
        or not isinstance(source_path, str)
        or not source_path
    ):
        return None
    alias = _closed_declaration_program(node, call_name)
    if alias is None:
        return None
    parsed = _exact_source_call(source_bytes, node)
    if parsed is None:
        return None
    tree, call = parsed
    if not _closed_declaration_binding(tree, call):
        return None
    if not _closed_declaration_namespace(tree, call, alias):
        return None
    return call


def captured_sink_evidence(
    node,
    *,
    source_path,
    source_sha256,
    source_index=None,
    source_bytes=None,
    tree=None,
    max_sources=64,
    max_states=512,
    max_output_bytes=64000,
):
    """Expose the shared captured-source sink ledger to native validators."""
    return _finite_capture.captured_sink_evidence(
        node,
        source_path=source_path,
        source_sha256=source_sha256,
        source_index=source_index,
        source_bytes=source_bytes,
        tree=tree,
        max_sources=max_sources,
        max_states=max_states,
        max_output_bytes=max_output_bytes,
    )


def closed_declaration_input_witness(node, call_name, *, source_bytes, source_path):
    """Recognize fixed Python 3.12 alias input without compiling or executing it."""
    call = _closed_declaration_source_call(node, call_name, source_bytes, source_path)
    if call is None:
        return {}
    return {
        "schema": "factory.closed-declaration-input.v1",
        "disposition": "PROVEN_CLOSED_DECLARATION_INPUT",
        "source_path": source_path,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "call_span": _source_span(call),
        "literal_span": _source_span(call.args[0]),
        "program_sha256": hashlib.sha256(call.args[0].value.encode()).hexdigest(),
        "grammar_profile": "python3.12-type-alias-subset-v1",
        "hypothesis": "ARGUMENT_CODE_INJECTION",
        "input_effect": "CLOSED_INERT_DECLARATION",
        "runtime_assurance": "INCOMPLETE",
        "target_execution": "not_performed",
    }


def _fixed_literal_call(node, call_name):
    normalized = {
        "eval": "eval",
        "builtins.eval": "eval",
        "__builtin__.eval": "eval",
        "exec": "exec",
        "builtins.exec": "exec",
        "__builtin__.exec": "exec",
    }
    normalized = normalized.get(call_name) if isinstance(call_name, str) else None
    if (
        normalized is None
        or not isinstance(node, ast.Call)
        or len(node.args) != 1
        or node.keywords
        or not isinstance(node.args[0], ast.Constant)
        or type(node.args[0].value) is not str
    ):
        return None
    return normalized, node.args[0]


def fixed_eval_workspace_helpers():
    """Bind both legacy exports and actual capture callees into the cache epoch."""
    names = (
        "_fixed_program_span",
        "_fixed_eval_name_hazard",
        "_fixed_eval_import_hazard",
        "_fixed_eval_attribute_hazard",
        "_fixed_eval_builtin_source_clear",
        "_fixed_eval_builtin_aliases",
        "_fixed_eval_provider_root",
        "_fixed_eval_provider_capability",
        "_fixed_eval_provider_alias_escape",
        "_fixed_eval_builtin_write",
        "_fixed_eval_builtin_subscript",
        "_fixed_eval_builtin_reflection",
        "_fixed_eval_dynamic_import_risk",
        "_fixed_eval_module_alias_escape",
        "_fixed_eval_module_scope",
        "_fixed_eval_interpreter_aliases",
        "_fixed_eval_interpreter_call",
        "_fixed_eval_callable_reaches_risk",
        "_fixed_eval_class_init_hooks",
        "_fixed_eval_local_class_aliases",
        "_fixed_eval_local_function_risks",
        "_fixed_eval_local_class_risks",
        "_fixed_eval_module_init_constructor_call",
        "_fixed_eval_module_init_risky_reference",
        "_fixed_eval_interpreter_payload",
        "_fixed_eval_nested_interpreter_risk",
        "_fixed_eval_local_init_call_risk",
        "_fixed_eval_builtin_provider_risk",
        "fixed_eval_workspace_provider_clear",
        "_fixed_eval_sink_context",
        "_fixed_eval_control_flow",
        "_fixed_eval_sink_statement",
        "_fixed_eval_parameters",
        "_fixed_eval_external_state",
        "_fixed_eval_row",
        "_fixed_eval_is_bytes_decode",
        "_fixed_eval_decode_state",
        "_fixed_eval_assignment_state",
        "_fixed_eval_local_states",
        "_fixed_eval_definition_rows",
        "_fixed_eval_proof",
        "fixed_eval_local_input_witness",
        "_fixed_literal_program_kinds",
        "_fixed_literal_value",
    )
    return (
        fixed_eval_workspace_helpers,
        *(globals()[name] for name in names),
        *(getattr(_finite_capture, name) for name in names),
    )


def _fixed_program_call_context(
    node, call_name, source_bytes, builtin_identity_proven, source_path
):
    call = _fixed_literal_call(node, call_name)
    if (
        call is None
        or builtin_identity_proven is not True
        or not isinstance(source_bytes, bytes)
        or not isinstance(source_path, str)
        or not source_path
    ):
        return None
    normalized, literal = call
    program = literal.value
    try:
        program_bytes = program.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if len(program_bytes) > 16 * 1024:
        return None
    statement_kinds, _ = _fixed_literal_program_kinds(program, normalized)
    if statement_kinds is None:
        return None
    return normalized, literal, program_bytes, statement_kinds


def _fixed_program_literal_span(literal):
    span = {
        key: getattr(literal, attr, None)
        for key, attr in (
            ("line", "lineno"),
            ("column", "col_offset"),
            ("end_line", "end_lineno"),
            ("end_column", "end_col_offset"),
        )
    }
    if any(type(value) is not int or value < 0 for value in span.values()):
        return None
    return span


def fixed_literal_program_witness(
    node,
    call_name,
    *,
    source_bytes,
    builtin_identity_proven,
    source_path=None,
    scope_profile=None,
):
    """Describe a tiny fixed eval/exec program; never execute the target text."""
    context = _fixed_program_call_context(
        node, call_name, source_bytes, builtin_identity_proven, source_path
    )
    if context is None:
        if builtin_identity_proven is not True:
            return {}
        input_proof = fixed_eval_local_input_witness(
            node, call_name, source_bytes=source_bytes, source_path=source_path
        )
        if not input_proof:
            return {}
        source_span = input_proof["program_source_span"]
        span = {
            "line": source_span[0],
            "column": source_span[1],
            "end_line": source_span[2],
            "end_column": source_span[3],
        }
        return {
            "schema": "factory.fixed-literal-program.v1",
            "disposition": "PROVEN_FIXED_LITERAL_PROGRAM",
            "source_path": source_path,
            "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "call_span": input_proof["call_span"],
            "literal_span": span,
            "program_sha256": input_proof["program_sha256"],
            "statement_kinds": input_proof["statement_kinds"],
            "def_use_witness": input_proof,
            "profile": {
                "call": "builtins.eval",
                "identity": "caller_proved_lexical_source_context",
                "namespace": "implicit_caller_namespace",
                "scope": scope_profile if isinstance(scope_profile, str) else None,
                "input_resolution": "ordered-local-strong-updates",
                "provider_scope": "source-visible provider checks; runtime isolation unproven",
                "runtime_assurance": "INCOMPLETE",
                "target_execution": "not_performed",
                "max_program_bytes": 16 * 1024,
                "max_ast_nodes": 1024,
            },
        }
    normalized, literal, program_bytes, statement_kinds = context
    span = _fixed_program_literal_span(literal)
    if span is None:
        return {}
    return {
        "schema": "factory.fixed-literal-program.v1",
        "disposition": "PROVEN_FIXED_LITERAL_PROGRAM",
        "source_path": source_path,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "call_span": _fixed_program_span(node),
        "literal_span": span,
        "program_sha256": hashlib.sha256(program_bytes).hexdigest(),
        "statement_kinds": statement_kinds,
        "profile": {
            "call": f"builtins.{normalized}",
            "identity": "caller_proved_lexical_source_context",
            "namespace": "implicit_caller_namespace",
            "scope": scope_profile if isinstance(scope_profile, str) else None,
            "provider_scope": "source-visible provider checks; runtime isolation unproven",
            "runtime_assurance": "INCOMPLETE",
            "target_execution": "not_performed",
            "max_program_bytes": 16 * 1024,
            "max_ast_nodes": 1024,
        },
    }


def _source_eval_span(node):
    return [
        getattr(node, key, None)
        for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ]


def _source_eval_call(node):
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "eval"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.JoinedStr)
    )


def _source_eval_tree(node, source_bytes):
    try:
        tree = ast.parse(source_bytes)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return None
    nodes, parents, pending = [], {}, [tree]
    while pending:
        current = pending.pop()
        nodes.append(current)
        if len(nodes) > 20_000:
            return None
        children = list(ast.iter_child_nodes(current))
        parents.update((child, current) for child in children)
        pending.extend(children)
    matches = [
        item
        for item in nodes
        if isinstance(item, ast.Call)
        and _source_eval_span(item) == _source_eval_span(node)
    ]
    if len(matches) != 1 or ast.dump(matches[0]) != ast.dump(node):
        return None
    return nodes, parents, matches[0]


def _source_eval_comprehension(call, parents):
    comprehensions, current = [], parents.get(call)
    while current is not None:
        if isinstance(
            current, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            comprehensions.append(current)
        current = parents.get(current)
    if len(comprehensions) != 1 or not isinstance(comprehensions[0], ast.ListComp):
        return None
    result = comprehensions[0]
    if len(result.generators) != 1 or not isinstance(result.elt, ast.Tuple):
        return None
    generator = result.generators[0]
    return result if not generator.is_async and not generator.ifs else None


def _source_eval_calls(comprehension, nodes):
    calls = [
        item
        for item in nodes
        if isinstance(item, ast.Call)
        and isinstance(item.func, ast.Name)
        and item.func.id in {"eval", "exec"}
    ]
    direct = [item for item in comprehension.elt.elts if _source_eval_call(item)]
    if not direct or calls != [item for item in nodes if item in direct]:
        return []
    if comprehension.elt.elts[: len(direct)] != direct:
        return []
    for item in ast.walk(comprehension.elt):
        if isinstance(item, ast.Call) and item not in direct:
            return []
        if isinstance(
            item, (ast.If, ast.IfExp, ast.BoolOp, ast.NamedExpr, ast.Await, ast.Yield)
        ):
            return []
    return direct


def _source_eval_target_names(target):
    names = target.elts if isinstance(target, (ast.Tuple, ast.List)) else [target]
    if not names or any(
        not isinstance(item, ast.Name) or not isinstance(item.ctx, ast.Store)
        for item in names
    ):
        return []
    return names if len({item.id for item in names}) == len(names) else []


def _source_eval_rows(generator):
    names = _source_eval_target_names(generator.target)
    domain = generator.iter
    if (
        not names
        or not isinstance(domain, (ast.Tuple, ast.List))
        or not 1 <= len(domain.elts) <= 64
    ):
        return []
    destructures = isinstance(generator.target, (ast.Tuple, ast.List))
    result = []
    for row in domain.elts:
        if destructures != isinstance(row, (ast.Tuple, ast.List)):
            return []
        values = row.elts if destructures else [row]
        if len(values) != len(names) or not _source_eval_scalar_values(values):
            return []
        result.append({name.id: value.value for name, value in zip(names, values)})
    return result


def _source_eval_scalar_values(values):
    return all(
        isinstance(value, ast.Constant)
        and type(value.value) in {str, bytes, int, bool, type(None)}
        for value in values
    )


def _source_eval_render(template, values):
    pieces = []
    for part in template.values:
        if isinstance(part, ast.Constant) and type(part.value) is str:
            pieces.append(part.value)
        elif (
            isinstance(part, ast.FormattedValue)
            and part.conversion == 114
            and part.format_spec is None
            and isinstance(part.value, ast.Name)
            and part.value.id in values
        ):
            pieces.append(repr(values[part.value.id]))
        else:
            return None
    return "".join(pieces)


def _source_eval_program(program):
    if program is None:
        return None
    try:
        encoded = program.encode("utf-8")
        parsed = ast.parse(program, mode="eval")
    except (
        SyntaxError,
        ValueError,
        TypeError,
        MemoryError,
        RecursionError,
        UnicodeError,
    ):
        return None
    if (
        len(encoded) > 16 * 1024
        or not isinstance(parsed.body, ast.Lambda)
        or parsed.body.args.defaults
        or parsed.body.args.kw_defaults
    ):
        return None
    nodes = sum(1 for _ in ast.walk(parsed))
    return (len(encoded), nodes) if nodes <= 1024 else None


def _source_eval_programs(calls, rows):
    programs_by_call, total_bytes, total_nodes = {}, 0, 0
    for call in calls:
        programs = []
        for values in rows:
            program = _source_eval_render(call.args[0], values)
            size = _source_eval_program(program)
            if size is None:
                return {}
            total_bytes += size[0]
            total_nodes += size[1]
            if total_bytes > 16 * 1024 or total_nodes > 1024:
                return {}
            programs.append(program)
        programs_by_call[call] = programs
    return programs_by_call


def _source_eval_call_shape(call_name, node):
    return call_name == "eval" and _source_eval_call(node)


def _source_eval_source_bound(proven, source_bytes, source_path):
    return (
        proven is True
        and isinstance(source_bytes, bytes)
        and len(source_bytes) <= 1024 * 1024
        and isinstance(source_path, str)
        and bool(source_path)
    )


def _source_generated_eval_capture(node, call_name, source_bytes, source_path, proven):
    if not _source_eval_call_shape(call_name, node) or not _source_eval_source_bound(
        proven, source_bytes, source_path
    ):
        return None
    captured = _source_eval_tree(node, source_bytes)
    if captured is None:
        return None
    nodes, parents, call = captured
    comprehension = _source_eval_comprehension(call, parents)
    if comprehension is None:
        return None
    calls = _source_eval_calls(comprehension, nodes)
    rows = _source_eval_rows(comprehension.generators[0])
    programs = _source_eval_programs(calls, rows) if rows else {}
    if call not in programs:
        return None
    return call, comprehension, rows, programs


def source_generated_eval_input_witness(
    node, call_name, *, source_bytes, source_path, builtin_identity_proven=False
):
    """Bind finite source-generated lambda strings; never execute their bodies."""
    captured = _source_generated_eval_capture(
        node, call_name, source_bytes, source_path, builtin_identity_proven
    )
    if captured is None:
        return {}
    call, comprehension, rows, programs = captured
    import json

    return {
        "schema": "factory.finite-eval-input.v1",
        "disposition": "PROVEN_FINITE_LITERAL_EVAL_INPUT",
        "source_path": source_path,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "call_span": _source_eval_span(call),
        "domain_span": _source_eval_span(comprehension.generators[0].iter),
        "comprehension_span": _source_eval_span(comprehension),
        "program_sha256": hashlib.sha256(
            json.dumps(programs[call], separators=(",", ":")).encode()
        ).hexdigest(),
        "domain_size": len(rows),
        "hypothesis": "ARGUMENT_CODE_INJECTION",
        "scope_profile": "single-comprehension-source-template",
        "input_effect": "CLOSED_SOURCE_GENERATED_STRINGS",
        "runtime_assurance": "INCOMPLETE",
        "target_execution": "not_performed",
    }


def _workspace_namespace_hazard(node, parent=None):
    if isinstance(node, ast.Name) and node.id in {"eval", "exec"}:
        return not (isinstance(parent, ast.Call) and parent.func is node)
    if isinstance(
        node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    ) and node.name in {"eval", "exec"}:
        return True
    if isinstance(node, ast.arg) and node.arg in {"eval", "exec"}:
        return True
    if isinstance(node, ast.Import) and any(
        alias.name.split(".", 1)[0] in {"builtins", "__builtin__"}
        for alias in node.names
    ):
        return True
    if isinstance(node, ast.ImportFrom) and (
        node.module in {"builtins", "__builtin__"}
        or any(a.name == "*" for a in node.names)
    ):
        return True
    if isinstance(node, ast.Name) and node.id in {
        "__builtins__",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
        "__import__",
    }:
        return True
    if not isinstance(node, ast.Attribute):
        return False
    if node.attr in {
        "__dict__",
        "__globals__",
        "__builtins__",
        "__getattribute__",
        "__setattr__",
        "import_module",
        "getattr",
        "setattr",
        "delattr",
    }:
        return True
    return node.attr in {"exec", "eval", "AssertionError"} and isinstance(
        node.ctx, (ast.Store, ast.Del)
    )


def _workspace_dynamic_exec_risk(node, remaining_nodes):
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"exec", "eval"}
    ):
        return False, 0, True
    call = _fixed_literal_call(node, node.func.id)
    if call is None:
        return True, 0, True
    normalized, literal = call
    try:
        if len(literal.value.encode("utf-8")) > 16 * 1024:
            return True, 0, True
    except UnicodeEncodeError:
        return True, 0, True
    kinds, examined = _fixed_literal_program_kinds(
        literal.value, normalized, node_limit=remaining_nodes
    )
    return kinds is None, examined, examined <= remaining_nodes


def _workspace_source_hashes(snapshots, files):
    if not isinstance(snapshots, dict) or not isinstance(files, list) or not snapshots:
        return None
    try:
        file_paths = set(files)
    except TypeError:
        return None
    if len(file_paths) != len(files) or file_paths != set(snapshots):
        return None
    source_hashes = {}
    for path in sorted(snapshots, key=str):
        tree = snapshots[path]
        digest = getattr(tree, "_oracle_source_sha256", None)
        if (
            not isinstance(tree, ast.Module)
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            return None
        source_hashes[str(path)] = digest
    return source_hashes


def workspace_builtin_profile(snapshots, files):
    """Summarize namespace hazards over the complete verified AST index."""
    profile = {
        "complete": False,
        "namespace_mutation_risk": True,
        "eval_provider_mutation_risk": True,
        "nodes_examined": 0,
        "source_hashes": {},
    }
    source_hashes = _workspace_source_hashes(snapshots, files)
    if source_hashes is None:
        return profile
    profile["source_hashes"] = source_hashes
    eval_provider_mutation_risk = any(
        _fixed_eval_builtin_provider_risk(tree) for tree in snapshots.values()
    )
    nodes_examined = 0
    namespace_mutation_risk = False
    for path in sorted(snapshots, key=str):
        pending = [(snapshots[path], None)]
        while pending:
            node, parent = pending.pop()
            nodes_examined += 1
            if nodes_examined > 200_000:
                profile["nodes_examined"] = nodes_examined
                return profile
            if _workspace_namespace_hazard(node, parent):
                namespace_mutation_risk = True
            risk, extra_nodes, bounded = _workspace_dynamic_exec_risk(
                node, 200_000 - nodes_examined
            )
            nodes_examined += extra_nodes
            if not bounded or nodes_examined > 200_000:
                profile["nodes_examined"] = nodes_examined
                return profile
            namespace_mutation_risk |= risk
            pending.extend((child, node) for child in ast.iter_child_nodes(node))
    return {
        "complete": True,
        "namespace_mutation_risk": namespace_mutation_risk,
        "eval_provider_mutation_risk": eval_provider_mutation_risk,
        "eval_provider_scope": (
            "source-visible provider writes and module-init eval/exec; "
            "function-body sinks remain separate alerts; runtime isolation unproven"
        ),
        "nodes_examined": nodes_examined,
        "source_hashes": source_hashes,
    }


def workspace_builtin_helpers():
    """Return workspace builtin and source-analysis helpers used by fixed-program and literal-input proofs."""
    from . import pickle_model_audit

    return (
        _workspace_namespace_hazard,
        _workspace_dynamic_exec_risk,
        _workspace_source_hashes,
        _fixed_literal_call,
        _source_eval_span,
        _source_eval_call,
        _source_eval_tree,
        _source_eval_comprehension,
        _source_eval_calls,
        _source_eval_target_names,
        _source_eval_rows,
        _source_eval_scalar_values,
        _source_eval_render,
        _source_eval_program,
        _source_eval_programs,
        _exact_source_call,
        _source_span,
        _closed_declaration_source_call,
        _fixed_program_call_context,
        _fixed_program_literal_span,
        _source_generated_eval_capture,
        _source_eval_call_shape,
        _source_eval_source_bound,
        _finite_eval_profile,
        _finite_eval_domain_digest,
        _finite_eval_spans,
        source_generated_eval_input_witness,
        finite_eval_binding,
        _test_serialization_roundtrip,
        _plain_scope_statement_index,
        _simple_scope_assignment,
        _prior_pickle_dump,
        _single_local_pickle_bytes_flow,
        closed_literal_pickle_witness,
        closed_local_pickle_flow,
        closed_local_pickle_origin,
        local_pickle_byte_origin,
        *(
            value
            for name, value in sorted(globals().items())
            if name.startswith(("_pickle_", "_local_pickle", "_conditional_"))
            and callable(value)
        ),
        *pickle_model_audit.cache_helpers(),
    )


def _expected_lanes(plan):
    lanes = plan["lanes"]
    expected = {lane["id"]: lane["kind"] for lane in lanes}
    if (
        len(lanes) != len(LANES)
        or len(expected) != len(LANES)
        or sorted(expected.values()) != sorted(LANES)
    ):
        raise RuntimeAuditError(
            "E_AUDIT_LANE_SET", "exactly one signed lane of each kind required"
        )
    return expected


def index_executions(plan, executions):
    """Reject ambiguous execution collections rather than silently overwriting evidence."""
    expected = _expected_lanes(plan)
    entries = executions.get("executions", [])
    if not isinstance(entries, list) or len(entries) > len(LANES):
        raise RuntimeAuditError(
            "E_AUDIT_EXECUTION_SET", "bounded execution list required"
        )
    result = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise RuntimeAuditError(
                "E_AUDIT_EXECUTION_SET", "execution identity required"
            )
        key = entry["id"]
        if key in result or key not in expected or entry.get("kind") != expected[key]:
            raise RuntimeAuditError(
                "E_AUDIT_EXECUTION_SET",
                "duplicate, unknown or mismatched execution identity",
            )
        result[key] = entry
    return result


def repair_guidance(result, lane):
    """Separate evidence repair from application repair without granting execution authority."""
    evidence_problem = (
        result["state"] == "INCOMPLETE" or result["finding"] == "HOLLOW_RUNTIME_AUDIT"
    )
    return {
        "action_summary": "Repair audit evidence before judging the application."
        if evidence_problem
        else "Review the observed application behavior against the signed obligation.",
        "repair_target": "audit_evidence"
        if evidence_problem
        else "application_behavior",
        "required": result["state"] != "PASS",
        "authority": "none",
        "target_argv": list(lane["target_argv"]),
        "negative_argv": list(lane["known_bad_argv"]),
        "expected_negative_code": lane["expected_negative_code"],
        "acceptance": "Target must pass and known-bad control must trigger the unchanged signed expected finding.",
        "execution_boundary": "Suggestions only; replay requires the verified plan and supervised runner.",
    }


def validate_receipt_decision(receipt):
    """Reject false readiness even when a local author recomputes the self-hash."""
    lanes = receipt.get("lanes")
    if not isinstance(lanes, list) or len(lanes) != len(LANES):
        raise RuntimeAuditError("E_RECEIPT_LANES", "complete six-lane receipt required")
    _validate_receipt_lanes(lanes)
    if (
        receipt.get("authority") != "none"
        or receipt.get("release_approval") is not False
    ):
        raise RuntimeAuditError(
            "E_RECEIPT_AUTHORITY", "runtime audit cannot authorize release"
        )
    boundary = receipt.get("runtime_boundary")
    boundary_blocked = isinstance(boundary, dict) and boundary.get("state") == "BLOCKED"
    expected = (
        "READY_FOR_HUMAN_REVIEW"
        if all(lane["state"] == "PASS" for lane in lanes) and not boundary_blocked
        else "BLOCKED"
    )
    if receipt.get("decision") != expected:
        raise RuntimeAuditError(
            "E_RECEIPT_DECISION", "decision contradicts lane results"
        )


def _validate_receipt_lanes(lanes):
    ids, kinds = set(), set()
    for lane in lanes:
        if not isinstance(lane, dict):
            raise RuntimeAuditError("E_RECEIPT_LANES", "lane object required")
        identity, kind = lane.get("id"), lane.get("lane")
        if not isinstance(identity, str) or not identity.strip() or identity in ids:
            raise RuntimeAuditError(
                "E_RECEIPT_LANES", "distinct nonempty lane identities required"
            )
        if not isinstance(kind, str) or kind not in LANES or kind in kinds:
            raise RuntimeAuditError(
                "E_RECEIPT_LANES", "distinct recognized lane kinds required"
            )
        if lane.get("state") not in ("PASS", "FAIL", "INCOMPLETE"):
            raise RuntimeAuditError("E_RECEIPT_LANES", "recognized lane state required")
        ids.add(identity)
        kinds.add(kind)


def _runtime_callback_nodes(test: ast.AST, test_qualname: str) -> dict[str, ast.AST]:
    callbacks = {}

    def visit(scope, qualname, class_scope=False):
        for child in ast.iter_child_nodes(scope):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                separator = "." if class_scope else ".<locals>."
                child_name = qualname + separator + child.name
                callbacks.setdefault(child_name, []).append(child)
                visit(child, child_name)
            elif isinstance(child, ast.ClassDef):
                child_name = qualname + ".<locals>." + child.name
                visit(child, child_name, class_scope=True)
            elif not isinstance(child, (ast.Lambda,)):
                visit(child, qualname, class_scope)

    visit(test, test_qualname)
    return callbacks


def _runtime_callback_rebound(test: ast.AST, callback: ast.AST) -> bool:
    for node in ast.walk(test):
        if isinstance(node, ast.Name) and node.id == callback.name:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                return True
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == callback.name
            and node.attr == "__code__"
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            return True
    return False


def _runtime_callback_frame_for_case(
    origins, case_id, test_path, test_sha, qualname=None
):
    return any(
        item["case_id"] == case_id
        and item["source_path"] == test_path
        and item["source_sha256"] == test_sha
        and item["observation_kind"] == "executed_frame"
        and (qualname is None or item.get("frame_qualname") == qualname)
        for item in origins
    )


def _runtime_callback_assertion_for_case(
    observations, case_id, qualname, line, outcome
):
    return any(
        row["case_id"] == case_id
        and row["callback_qualname"] == qualname
        and row["line"] == line
        and row["assertion_kind"] == "assert"
        and row["hits"] > 0
        and row["outcome"] == outcome
        and row["failure_visible"] is (outcome == "FAIL")
        for row in observations
    )


def _runtime_assertion_is_strong(assertion, strong_assertion, aliases):
    wrapper = ast.FunctionDef(
        name="test_runtime_assertion",
        args=ast.arguments(
            posonlyargs=[],
            args=[],
            vararg=None,
            kwonlyargs=[],
            kw_defaults=[],
            defaults=[],
        ),
        body=[assertion],
        decorator_list=[],
    )
    return strong_assertion(ast.fix_missing_locations(wrapper), aliases)


def _runtime_callback_context(oracle_row, test_qualname, current_config_manifest):
    baseline, mutation = oracle_row.get("baseline"), oracle_row.get("mutation")
    if not isinstance(baseline, dict) or not isinstance(mutation, dict):
        return None, "v3 baseline and mutation records are required"
    lifecycle = (
        baseline.get("status") == "PASS"
        and baseline.get("phase") == "call"
        and baseline.get("setup_status") == "PASS"
        and baseline.get("teardown_status") == "PASS"
        and mutation.get("status") == "FAIL"
        and mutation.get("phase") == "call"
        and mutation.get("setup_status") == "PASS"
        and mutation.get("teardown_status") == "PASS"
        and mutation.get("failure_kind") == "assertion"
    )
    if not lifecycle:
        return None, "baseline or visible assertion mutation lifecycle is incomplete"
    baseline_catalog = baseline.get("collection_catalog")
    mutation_catalog = mutation.get("collection_catalog")
    if not isinstance(baseline_catalog, dict) or not isinstance(mutation_catalog, dict):
        return None, "complete v3 function collection catalogs are required"
    catalogs = (baseline_catalog, mutation_catalog)
    if any(
        item.get("status") != "PASS"
        or item.get("phase") != "collection"
        or item.get("complete") is not True
        or item.get("scope") != "test_function"
        or item.get("source_path") != oracle_row["path"]
        or item.get("source_sha256") != oracle_row["test_sha256"]
        for item in catalogs
    ):
        return None, "signed function collection catalog is incomplete"
    if current_config_manifest is None:
        return None, "current static configuration binding is unavailable"
    manifest = [
        {"path": path, "sha256": digest}
        for path, digest in sorted(current_config_manifest.items())
    ]
    identity = "manifest" if manifest else "pytest-default"
    if any(
        item["config_manifest"] != manifest or item["config_identity"] != identity
        for item in catalogs
    ):
        return None, "collection config does not match current scan config"
    if baseline_catalog["case_ids"] != mutation_catalog["case_ids"]:
        return None, "baseline and mutation collection scope differs"
    prefix = oracle_row["path"] + "::" + test_qualname.replace(".", "::")
    catalog_cases = baseline_catalog["case_ids"]
    if any(
        case != prefix and not case.startswith(prefix + "[") for case in catalog_cases
    ):
        return None, "collection catalog does not match the exact test qualname"
    if baseline["case_ids"] != mutation["case_ids"]:
        return None, "baseline and mutation selected cases differ"
    return (baseline, mutation, catalog_cases), None


def _runtime_callback_case_match(
    case_id, qualname, assertions, oracle_row, baseline, mutation
):
    if case_id not in baseline["case_ids"] or case_id not in mutation["case_ids"]:
        return False
    path, test_sha = oracle_row["path"], oracle_row["test_sha256"]
    baseline_origins, mutation_origins = (
        baseline["module_origins"],
        mutation["module_origins"],
    )
    for assertion in assertions:
        if (
            _runtime_callback_frame_for_case(
                baseline_origins, case_id, path, test_sha, qualname
            )
            and _runtime_callback_frame_for_case(
                mutation_origins, case_id, path, test_sha, qualname
            )
            and _runtime_callback_frame_for_case(
                baseline_origins,
                case_id,
                mutation["source_path"],
                mutation["source_sha256"],
            )
            and _runtime_callback_frame_for_case(
                mutation_origins,
                case_id,
                mutation["source_path"],
                mutation["mutant_sha256"],
            )
            and _runtime_callback_assertion_for_case(
                baseline["assertion_observations"],
                case_id,
                qualname,
                assertion.lineno,
                "PASS",
            )
            and _runtime_callback_assertion_for_case(
                mutation["assertion_observations"],
                case_id,
                qualname,
                assertion.lineno,
                "FAIL",
            )
        ):
            return True
    return False


def _runtime_callback_covered(
    test,
    test_qualname,
    catalog,
    oracle_row,
    baseline,
    mutation,
    aliases,
    strong_assertion,
    effective_assertion,
):
    from .review_integrity import _callback_has_live_assertion, _lexical_nodes

    covered, used = set(), set()
    candidates = _runtime_callback_nodes(test, test_qualname)
    for qualname, nodes in candidates.items():
        if len(nodes) != 1 or not qualname.startswith(test_qualname + ".<locals>."):
            continue
        callback = nodes[0]
        if _runtime_callback_rebound(
            test, callback
        ) or not _callback_has_live_assertion(
            callback, aliases, strong_assertion, effective_assertion
        ):
            continue
        assertions = [
            node
            for node in _lexical_nodes(callback)
            if isinstance(node, ast.Assert)
            and effective_assertion(node, aliases)
            and _runtime_assertion_is_strong(node, strong_assertion, aliases)
        ]
        matched = {
            case_id
            for case_id in catalog
            if _runtime_callback_case_match(
                case_id, qualname, assertions, oracle_row, baseline, mutation
            )
        }
        if matched:
            covered.update(matched)
            used.add(qualname)
    return covered, used


def runtime_callback_coverage(
    test: ast.AST,
    oracle_row: dict,
    *,
    verified_schema: str,
    test_qualname: str,
    current_config_manifest: dict[str, str] | None,
    strong_assertion,
    effective_assertion,
    aliases: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Reconcile exact signed callback assertion coverage without clearing partial cases."""
    result = {
        "eligible": False,
        "covered_case_ids": [],
        "remaining_case_ids": [],
        "callback_qualnames": [],
        "reason": "runtime callback evidence is incomplete",
    }
    baseline = oracle_row.get("baseline")
    if isinstance(baseline, dict):
        catalog = baseline.get("collection_catalog")
        if isinstance(catalog, dict) and isinstance(catalog.get("case_ids"), list):
            result["remaining_case_ids"] = list(catalog["case_ids"])
    if verified_schema != "factory.test-oracle-verification.v3":
        result["reason"] = "verified v3 origin and assertion schema is required"
        return result
    context, reason = _runtime_callback_context(
        oracle_row, test_qualname, current_config_manifest
    )
    if reason:
        result["reason"] = reason
        return result
    baseline, mutation, catalog = context
    result["remaining_case_ids"] = list(catalog)
    aliases = aliases or {}
    covered, used_callbacks = _runtime_callback_covered(
        test,
        test_qualname,
        catalog,
        oracle_row,
        baseline,
        mutation,
        aliases,
        strong_assertion,
        effective_assertion,
    )
    result["covered_case_ids"] = sorted(covered)
    result["remaining_case_ids"] = sorted(set(catalog) - covered)
    result["callback_qualnames"] = sorted(used_callbacks)
    result["eligible"] = not result["remaining_case_ids"]
    result["reason"] = (
        "all collected cases have matching visible callback assertion failures"
        if result["eligible"]
        else "callback evidence covers only a subset of the function collection"
    )
    return result


def assigned_sync_function_call(
    call: ast.Call, scope: ast.AST, module: ast.AST, async_only=False
) -> bool:
    """Resolve one stable direct helper; async mode reports discarded coroutines."""
    if isinstance(call.func, ast.Lambda):
        return not async_only
    if not isinstance(call.func, ast.Name):
        return False
    kind = ast.AsyncFunctionDef if async_only else ast.FunctionDef
    candidates, body = _oracle_call_candidates(call.func.id, scope, module, kind)
    return len(candidates) == 1 and _oracle_stable_call(
        candidates[0], call, scope, body, async_only
    )


def _oracle_call_candidates(name, scope, module, kind):
    from .review_audits import _scope_parameters

    local = [
        item for item in scope.body if isinstance(item, kind) and item.name == name
    ]
    body = scope.body if local else module.body
    if not local and (
        name in _scope_parameters(scope)
        or any(name in _oracle_bound_names(stmt) for stmt in scope.body)
    ):
        return [], body
    return local or [
        item for item in body if isinstance(item, kind) and item.name == name
    ], body


def _oracle_stable_call(candidate, call, scope, body, async_only):
    from .review_audits import _body_nodes

    if candidate.decorator_list:
        return False
    if candidate.lineno >= call.lineno and (body is scope.body or not async_only):
        return False
    if async_only and any(
        isinstance(child, ast.Yield)
        for stmt in candidate.body
        for child in _body_nodes(stmt)
    ):
        return False
    bindings = [name for stmt in body for name in _oracle_bound_names(stmt)]
    return [name for name in bindings if name in {call.func.id, "*"}] == [call.func.id]


def _later_test_binding(owner, node):
    for item in getattr(owner, "body", ()):
        if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if item.name == node.name and item.lineno > node.lineno:
            return item
    return None


def _asserted_coroutine_call(child, following):
    assigned = (
        isinstance(child, ast.Assign)
        and len(child.targets) == 1
        and isinstance(child.targets[0], ast.Name)
        and isinstance(following, ast.Assert)
        and isinstance(following.test, ast.Name)
        and following.test.id == child.targets[0].id
    )
    assertion = (
        following if assigned else child if isinstance(child, ast.Assert) else None
    )
    return assertion, child.value if assigned else assertion.test if assertion else None


def test_execution_findings(node, relative, parents, module):
    """Report shadowed tests and local async helpers used without awaiting."""
    from .review_audits import _body_nodes, _security_finding

    owner = (parents.get(id(node)) or ((module, node),))[-1][0]
    shadow = _later_test_binding(owner, node)
    if shadow:
        return [
            _security_finding(
                "QUALITY_SHADOWED_TEST",
                relative,
                node,
                "A later direct test definition replaces this test binding.",
                "MEDIUM",
                symbol=node.name,
                shadowed_by_line=shadow.lineno,
            )
        ], True
    findings = []
    for child, following in zip(node.body, [*node.body[1:], None]):
        assertion, call = _asserted_coroutine_call(child, following)
        if isinstance(call, ast.Call) and assigned_sync_function_call(
            call, node, module, True
        ):
            findings.append(
                _unawaited_coroutine_finding(relative, assertion, node.name)
            )
    findings += [
        _unawaited_coroutine_finding(relative, child, node.name)
        for child in _body_nodes(ast.Module(body=node.body, type_ignores=[]))
        if isinstance(child, ast.Expr)
        and isinstance(child.value, ast.Call)
        and assigned_sync_function_call(child.value, node, module, True)
    ]
    return findings, False


def _unawaited_coroutine_finding(relative, source, symbol):
    from .review_audits import _security_finding

    return _security_finding(
        "QUALITY_UNAWAITED_COROUTINE",
        relative,
        source,
        "Local async helper is used without awaiting its result.",
        "MEDIUM",
        symbol=symbol,
    )


def _nearest_native_function_scope(node: ast.AST, parents: dict) -> bool:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(
            current,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            return isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef))
    return False


def _native_call_probe_lines(node: ast.AST) -> list[int]:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []
    walked = list(ast.walk(node))
    parents = {
        child: parent for parent in walked for child in ast.iter_child_nodes(parent)
    }
    statements: dict[int, list[ast.stmt]] = {}
    for child in walked:
        if isinstance(child, ast.stmt):
            statements.setdefault(child.lineno, []).append(child)
    lines = set()
    for child in walked:
        if not isinstance(child, ast.Expr):
            continue
        if not isinstance(child.value, ast.Call):
            continue
        if not _nearest_native_function_scope(child, parents):
            continue
        if statements.get(child.lineno) != [child]:
            continue
        if sum(isinstance(part, ast.Call) for part in ast.walk(child.value)) != 1:
            continue
        lines.add(child.lineno)
    return sorted(lines)[:32]


def native_test_probe(relative: str, node: ast.AST) -> dict[str, Any]:
    """Build advisory assertion and standalone-call probe guidance for one test."""
    lines = sorted(
        {child.lineno for child in ast.walk(node) if isinstance(child, ast.Assert)}
    )[:32]
    call_lines = _native_call_probe_lines(node)
    command = [
        "python",
        "-m",
        "factoryline.pytest_readiness",
        "--root",
        ".",
        "--nodeid",
        "<exact collected pytest node ID>",
        "--line",
        "<assertion line>",
        "--timeout",
        "30",
    ]
    call_command = [
        "python",
        "-m",
        "factoryline.pytest_readiness",
        "--kind",
        "call",
        "--root",
        ".",
        "--nodeid",
        "<exact collected pytest node ID>",
        "--line",
        "<call line>",
        "--timeout",
        "30",
    ]
    return {
        "available": bool(lines),
        "assertion_lines": lines,
        "nodeid_hint": relative + "::" + getattr(node, "name", ""),
        "exact_collection_id_required": True,
        "command": command,
        "execution": "Explicit local execution only; never started by a static scan",
        "interpretation": "Reachability and failure propagation only; review semantic strength separately; no automatic suppression",
        "call_available": bool(call_lines),
        "call_lines": call_lines,
        "call_command": call_command,
        "call_limits": [
            "Candidates are standalone call statements only; the runtime CLI validates the exact target again",
            "Injection is before the selected statement and reports reachability and failure escape only",
            "Production-function mutation sensitivity and semantic quality are not assessed",
            "No automatic detection change, finding clearance, or execution by static scan",
        ],
    }


def _oracle_bound_names(statement):
    from .review_integrity import _oracle_bound_names as resolve

    return resolve(statement)


def native_execution_helpers():
    """Return helpers that analyze native test execution and correlated source-bound calls."""
    from . import pickle_model_audit

    return (
        assigned_sync_function_call,
        _oracle_call_candidates,
        _oracle_stable_call,
        _later_test_binding,
        _asserted_coroutine_call,
        test_execution_findings,
        _unawaited_coroutine_finding,
        _nearest_native_function_scope,
        _native_call_probe_lines,
        native_test_probe,
        _oracle_bound_names,
        closed_local_pickle_origin,
        *pickle_model_audit.cache_helpers(),
    )


def credential_validation_helpers():
    """Collect callable validators from the credential-related analysis modules while excluding imported callables."""
    from . import (
        credential_endpoint_admission,
        credential_role_constructor_provider as credential_role_scope_bindings,
    )
    from . import (
        finite_capture,
        semantic_credential_sensor,
        primitive_observation_binding,
    )

    modules = (
        credential_role_scope_bindings,
        finite_capture,
        primitive_observation_binding,
        *semantic_credential_sensor.validation_modules(),
    )
    return (
        *credential_endpoint_admission.validation_helpers(),
        *(
            value
            for module in modules
            for value in vars(module).values()
            if callable(value) and getattr(value, "__module__", None) == module.__name__
        ),
    )


def finite_template_input_helpers():
    """Return the finite-template capture and provider-closure helpers used by source analysis."""
    from . import pickle_model_audit

    return (
        credential_validation_helpers,
        *credential_validation_helpers(),
        _FiniteInputCapture,
        *(
            getattr(_FiniteInputCapture, name).__func__
            if isinstance(value, classmethod)
            else getattr(_FiniteInputCapture, name)
            for name, value in _FiniteInputCapture.__dict__.items()
            if name.startswith("_finite") or name == "finite_template_inputs"
        ),
        _finite_template_program_hash,
        finite_template_program_hashes,
        finite_template_capture_shape,
        finite_domain_reference_allowed,
        finite_provider_attribute_write_index,
        finite_blocked_provider_prefixes,
        finite_scope_binding_candidate,
        _LiteralConsumers._finite_pytest_provider_closed,
        _LiteralConsumers._finite_pytest_tree_closed,
        _LiteralConsumers._finite_pytest_name_closed,
        _LiteralConsumers._finite_module_initializer_safe,
        closed_literal_pickle_witness,
        closed_local_pickle_origin,
        *pickle_model_audit.cache_helpers(),
    )


def _finite_eval_profile(facts):
    return (
        type(facts.get("scope_profile")) is str
        and type(facts.get("input_effect")) is str
        and facts.get("schema") == "factory.finite-eval-input.v1"
        and facts.get("disposition") == "PROVEN_FINITE_LITERAL_EVAL_INPUT"
        and facts.get("hypothesis") == "ARGUMENT_CODE_INJECTION"
        and (facts.get("scope_profile"), facts.get("input_effect"))
        in {
            ("module-initializer-literal-table", "CLOSED_LITERAL_TYPE_EXPRESSIONS"),
            ("single-comprehension-source-template", "CLOSED_SOURCE_GENERATED_STRINGS"),
        }
        and facts.get("runtime_assurance") == "INCOMPLETE"
        and facts.get("target_execution") == "not_performed"
    )


def _finite_eval_domain_digest(facts):
    return (
        type(facts.get("domain_size")) is int
        and 1 <= facts["domain_size"] <= 64
        and isinstance(facts.get("program_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", facts["program_sha256"]) is not None
    )


def _finite_eval_spans(finding, facts, valid_source_span):
    if not valid_source_span(facts.get("call_span")):
        return False
    if facts["call_span"][:2] != [finding.get("line"), finding.get("column")]:
        return False
    if not valid_source_span(facts.get("domain_span")):
        return False
    if not valid_source_span(facts.get("comprehension_span")):
        return False
    return (
        tuple(facts["comprehension_span"][:2])
        <= tuple(facts["call_span"][:2])
        <= tuple(facts["call_span"][2:])
        <= tuple(facts["domain_span"][:2])
        <= tuple(facts["domain_span"][2:])
        <= tuple(facts["comprehension_span"][2:])
    )


def finite_eval_binding(finding, valid_source_span):
    """Validate finite-eval fields and source spans without implying execution proof."""
    facts = finding.get("facts", {})
    return (
        isinstance(facts, dict)
        and _finite_eval_profile(facts)
        and _finite_eval_domain_digest(facts)
        and _finite_eval_spans(finding, facts, valid_source_span)
    )


def _test_serialization_roundtrip(relative, node, aliases):
    """Classify direct or same-scope local serializer bytes in test sources."""
    from . import review_audits as audit

    path = Path(relative)
    if not (
        "tests" in path.parts
        or path.name.startswith("test_")
        or path.name.endswith("_test.py")
    ):
        return False
    if len(node.args) != 1 or node.keywords:
        return False
    loaded_name = audit._normalized_call_name(node, aliases)
    serialized = node.args[0]
    if isinstance(serialized, ast.Call):
        return (
            len(serialized.args) == 1
            and not isinstance(serialized.args[0], ast.Starred)
            and audit._normalized_call_name(serialized, aliases)
            == loaded_name.removesuffix("loads") + "dumps"
            and audit._call_name(serialized).split(".", 1)[0] in aliases
            and not any(keyword.arg is None for keyword in serialized.keywords)
        )
    return _local_pickle_roundtrip(node, loaded_name, aliases, audit)


def closed_literal_pickle_witness(relative, node, aliases):
    """Retain the runtime facade while delegating pickle proof to its model."""
    from .pickle_model_audit import closed_literal_pickle_witness as build_witness

    return build_witness(
        relative,
        node,
        aliases,
        fixed_literal_value=_finite_capture._fixed_literal_value,
        closed_pickle_inventory=_closed_pickle_inventory,
    )


def _closed_pickle_inventory(root, sources, audit):
    """Reject captured provider shadowing and mutation before granting a witness."""
    import json
    from itertools import islice

    if not isinstance(sources, dict) or len(sources) > 2000:
        return None
    if (
        any(
            not isinstance(raw, bytes) or len(raw) > 1_000_000
            for raw in sources.values()
        )
        or sum(map(len, sources.values())) > 32_000_000
    ):
        return None
    rows, records, provider_modules = [], [], set()
    for path, raw in sources.items():
        relative = path.relative_to(root)
        if any(part in {"pickle.py", "pickle"} for part in relative.parts):
            return None
        try:
            nodes = list(islice(ast.walk(ast.parse(raw)), 200_001))
        except (SyntaxError, ValueError, RecursionError):
            return None
        if len(nodes) > 200_000 or not _closed_pickle_provider_source(nodes, audit):
            return None
        records.append(nodes)
        provider_modules.update(_pickle_export_modules(relative, nodes, audit))
        rows.append((relative.as_posix(), hashlib.sha256(raw).hexdigest()))
    if any(not _pickle_exports_closed(nodes, provider_modules) for nodes in records):
        return None
    return hashlib.sha256(
        json.dumps(sorted(rows), separators=(",", ":")).encode()
    ).hexdigest()


def _pickle_export_modules(relative, nodes, audit):
    aliases = audit._security_aliases(nodes)
    if not any(
        origin == "pickle" or origin.startswith("pickle.")
        for origin in aliases.values()
    ):
        return set()
    parts = relative.with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    # All suffixes cover source roots such as src/pkg without guessing sys.path.
    return {".".join(parts[index:]) for index in range(len(parts))}


def _pickle_exports_closed(nodes, provider_modules):
    for node in nodes:
        if isinstance(node, ast.Import) and any(
            alias.name in provider_modules for alias in node.names
        ):
            return False
        if isinstance(node, ast.ImportFrom):
            if node.level or any(alias.name == "*" for alias in node.names):
                return False
            if node.module in provider_modules or any(
                f"{node.module}.{alias.name}" in provider_modules
                for alias in node.names
            ):
                return False
    return True


def _closed_pickle_provider_source(nodes, audit):
    from .intent_quality import _sanitizer_provider_mutated

    aliases = _finite_capture._shell_import_aliases(nodes, audit, "pickle")
    if aliases is None:
        return False
    namespace_paths = [
        audit._resolved_ast_name(node, aliases)
        for node in nodes
        if isinstance(node, ast.Attribute)
    ]
    if any(
        path == "sys.modules" or path.startswith("pickle.__")
        for path in namespace_paths
    ):
        return False
    parents = {
        id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    if _finite_capture._shell_dynamic_provider_access(
        nodes, aliases, audit, parents, "pickle"
    ) or not _finite_capture._shell_namespace_queries_closed(
        nodes, aliases, audit, parents, "pickle"
    ):
        return False
    module = next(node for node in nodes if isinstance(node, ast.Module))
    for head, origin in aliases.items():
        for leaf in ("loads", "dumps"):
            expected = "pickle." + leaf
            if origin not in {"pickle", expected}:
                continue
            function = ast.Name(id=head, ctx=ast.Load())
            if origin == "pickle":
                function = ast.Attribute(value=function, attr=leaf, ctx=ast.Load())
            call = ast.Call(func=function, args=[], keywords=[])
            if _sanitizer_provider_mutated(
                module, call, aliases, expected, head, audit
            ):
                return False
    return True


def _local_pickle_roundtrip(node, loaded_name, aliases, audit):
    """Prove an unaliased serialized local value and load in one test scope."""
    if not isinstance(node.args[0], ast.Name) or not loaded_name.endswith(".loads"):
        return False
    scope = getattr(node, "_oracle_scope", None)
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    load_index = _plain_scope_statement_index(node, scope)
    if load_index is None:
        return False
    bytes_name = node.args[0].id
    dump = _prior_pickle_dump(
        scope, bytes_name, load_index, loaded_name, aliases, audit
    )
    if dump is None:
        return False
    dump_index, dump_statement, dump_call, value_name = dump
    if not _local_pickle_value(scope, value_name, dump_index, dump_call.args[0], audit):
        return False
    module = getattr(scope, "_oracle_module", None)
    return (
        isinstance(module, ast.Module)
        and _pickle_call_imported(module, scope, dump_call, dump_index, aliases, audit)
        and _pickle_call_imported(module, scope, node, load_index, aliases, audit)
        and _single_local_pickle_bytes_flow(scope, bytes_name, dump_statement, node)
    )


def closed_local_pickle_flow(
    node, loaded_name, aliases, audit, *, serializer_namespace_only=False
):
    """Resolve a source-closed local serialization edge without assuming arbitrary object reconstruction is safe."""
    if not _pickle_load_call_shape(node, loaded_name):
        return None
    scope = getattr(node, "_oracle_scope", None) or getattr(
        node, "_security_lexical_scope", None
    )
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    ancestors = _pickle_flow_ancestors(node, scope, audit)
    scope_statement = next((item for owner, item in ancestors if owner is scope), None)
    module = _pickle_scope_module(scope)
    if scope_statement not in scope.body or module is None:
        return None
    for loop, load_statement in reversed(ancestors):
        witness = _closed_pickle_iteration_witness(
            node,
            loaded_name,
            aliases,
            audit,
            scope,
            scope_statement,
            module,
            loop,
            load_statement,
            serializer_namespace_only=serializer_namespace_only,
        )
        if witness is not None:
            return witness
    return None


def _pickle_load_call_shape(node, loaded_name, *, allow_nested=False):
    return (
        isinstance(node, ast.Call)
        and len(node.args) == 1
        and not node.keywords
        and (
            isinstance(node.args[0], ast.Name)
            or allow_nested
            and isinstance(node.args[0], ast.Call)
        )
        and loaded_name.endswith(".loads")
    )


def closed_local_pickle_origin(node, loaded_name, aliases, audit, *, serializer_namespace_only=False):
    """Retain the runtime facade while delegating native origin proof."""
    from .pickle_model_audit import closed_local_pickle_origin as find_origin

    return find_origin(
        node,
        loaded_name,
        aliases,
        audit,
        load_call_shape=_pickle_load_call_shape,
        direct_scope_index=_pickle_direct_scope_index,
        scope_module=_pickle_scope_module,
        direct_dump_origin=_pickle_direct_dump_origin,
        direct_protocol=_pickle_direct_protocol,
        serializer_imports_closed=lambda *args: _pickle_direct_serializer_imports_closed(
            *args, serializer_namespace_only=serializer_namespace_only
        ),
    )


def local_pickle_byte_origin(node, loaded_name, aliases, audit):
    """Describe a source-visible serializer edge independently of reconstructed types.

    This observation grants no primitive partition, safe-object or negative
    security decision. Reducer effects and runtime authority remain unassessed.
    """
    if loaded_name != "pickle.loads" or not _pickle_load_call_shape(
        node, loaded_name, allow_nested=True
    ):
        return None
    scope = getattr(node, "_oracle_scope", None)
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    module = _pickle_scope_module(scope)
    if module is None:
        return None
    selected = _pickle_byte_edge_dump(node, scope, aliases, audit)
    if selected is None:
        return None
    dump, payload = selected
    scope_statement = _conditional_v3_load_statement(node, scope)
    if scope_statement not in scope.body or not _pickle_byte_edge_dump_shape(dump):
        return None
    if not _pickle_serializer_imports_closed(
        module,
        scope,
        scope_statement,
        dump,
        node,
        aliases,
        audit,
        serializer_namespace_only=True,
    ):
        return None
    return {
        "schema": "factory.pickle.byte-origin.v1",
        "origin": "SOURCE_VISIBLE_PICKLE_DUMP_EDGE",
        "serializer_provider_identity": "UNASSESSED",
        "load_span": _fixed_program_span(node),
        "dump_span": _fixed_program_span(dump),
        "frame_span": _fixed_program_span(scope),
        "object_expression_sha256": _conditional_v3_ast_digest(dump.args[0]),
        "payload_binding": payload,
        "byte_replacement_on_captured_edge": "NO_SOURCE_VISIBLE_REASSIGNMENT",
        "reconstruction_effects": "UNASSESSED",
        "runtime_assurance": "INCOMPLETE",
        "negative_security_decision": False,
    }


def _pickle_byte_edge_dump(node, scope, aliases, audit):
    payload = node.args[0]
    if isinstance(payload, ast.Call):
        return (
            (payload, None)
            if audit._normalized_call_name(payload, aliases) == "pickle.dumps"
            else None
        )
    for owner, statement in reversed(_pickle_flow_ancestors(node, scope, audit)):
        body = getattr(owner, "body", None)
        if not isinstance(body, list) or statement not in body:
            continue
        matches = [
            (index, item, _simple_scope_assignment(item, payload.id))
            for index, item in enumerate(body[: body.index(statement)])
            if _simple_scope_assignment(item, payload.id) is not None
        ]
        if len(matches) != 1:
            continue
        position, assignment, dump = matches[0]
        if (
            isinstance(dump, ast.Call)
            and audit._normalized_call_name(dump, aliases) == "pickle.dumps"
        ):
            window = body[position : body.index(statement) + 1]
            return (
                (dump, payload.id)
                if _pickle_byte_edge_window_closed(
                    scope, window, assignment, node, payload.id
                )
                else None
            )
    return None


def _pickle_byte_edge_window_closed(scope, statements, assignment, load, name):
    from .context_efficiency import _capability_uses_match

    if any(
        isinstance(item, (ast.Global, ast.Nonlocal)) and name in item.names
        for item in ast.walk(scope)
    ):
        return False
    target = _pickle_statement_target(assignment)
    nodes = [node for statement in statements for node in ast.walk(statement)]
    return _capability_uses_match(nodes, name, [target, load.args[0]])


def _pickle_byte_edge_dump_shape(call):
    return (
        isinstance(call, ast.Call)
        and 1 <= len(call.args) <= 2
        and not any(isinstance(value, ast.Starred) for value in call.args)
        and all(item.arg == "protocol" for item in call.keywords)
        and len(call.keywords) <= 1
        and not (len(call.args) == 2 and call.keywords)
    )


def _pickle_direct_protocol(call):
    """Accept the default or one bounded literal protocol, with no extra options."""
    if not isinstance(call, ast.Call) or not call.args:
        return None
    if any(isinstance(argument, ast.Starred) for argument in call.args):
        return None
    protocol = None
    source = "omitted"
    if len(call.args) == 1 and not call.keywords:
        return {"kind": "default", "source": source}
    if len(call.args) == 2 and not call.keywords:
        protocol = call.args[1]
        source = "positional_literal"
    elif len(call.args) == 1 and len(call.keywords) == 1:
        keyword = call.keywords[0]
        if keyword.arg != "protocol":
            return None
        protocol = keyword.value
        source = "keyword_literal"
    else:
        return None
    if isinstance(protocol, ast.Constant) and protocol.value is None:
        return {"kind": "default", "source": "explicit_none"}
    if not _pickle_protocol_integer(protocol):
        return None
    value = ast.literal_eval(protocol)
    if value < -1 or value > 5:
        return None
    return {"kind": "integer", "value": value, "source": source}


def _pickle_direct_serializer_imports_closed(
    module, scope, dump_index, load_index, dump_call, load_call, aliases, audit,
    *, serializer_namespace_only=False,
):
    from .pickle_model_audit import pickle_serializer_imports_closed
    return pickle_serializer_imports_closed(module, scope, dump_index, load_index, dump_call, load_call, aliases, audit, _pickle_call_imported, _conditional_v3_alias_closure, serializer_namespace_only)


def _pickle_direct_scope_index(node, scope, audit):
    ancestors = _pickle_flow_ancestors(node, scope, audit)
    statement = next((child for owner, child in ancestors if owner is scope), None)
    if statement not in scope.body:
        return None
    controls = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.With,
        ast.AsyncWith,
        ast.Match,
        ast.IfExp,
        ast.BoolOp,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
    )
    if any(
        parent is not scope and isinstance(parent, controls) for parent, _ in ancestors
    ):
        return None
    return scope.body.index(statement)


def _pickle_flow_ancestors(node, scope, audit):
    ancestors = getattr(node, "_oracle_ancestors", ())
    if ancestors:
        return ancestors
    chain, child = [], node
    while child is not scope:
        parent = audit._security_parent(child)
        if parent is None:
            return ()
        chain.append((parent, child))
        child = parent
    return tuple(reversed(chain))


def _pickle_scope_module(scope):
    module = getattr(scope, "_oracle_module", None)
    if not isinstance(module, ast.Module):
        from .review_integrity import _security_module_scope

        module = _security_module_scope(scope)
    return module if isinstance(module, ast.Module) else None


def _closed_pickle_iteration_witness(
    node,
    loaded_name,
    aliases,
    audit,
    scope,
    scope_statement,
    module,
    loop,
    load_statement,
    *,
    serializer_namespace_only=False,
):
    if not isinstance(node.args[0], ast.Name):
        return None
    if not _pickle_protocol_loop_shape(loop, load_statement):
        return None
    protocol = _pickle_protocol_loop_range(loop, scope, module, aliases, audit)
    if protocol is None:
        return None
    dump = _pickle_dump_assignment(
        loop,
        load_statement,
        node.args[0].id,
        loaded_name,
        protocol,
        scope,
        aliases,
        audit,
        node,
    )
    if dump is None:
        return None
    dump_statement, dump_call = dump
    if not _pickle_serializer_imports_closed(
        module,
        scope,
        scope_statement,
        dump_call,
        node,
        aliases,
        audit,
        serializer_namespace_only=serializer_namespace_only,
    ):
        return None
    object_flow = _closed_pickle_object_flow(
        scope, loop, scope_statement, dump_call, audit
    )
    if object_flow is None:
        return None
    return {
        "status": "LOCAL_PROTOCOL_LOOP_ROUNDTRIP",
        "load_call": node,
        "dump_call": dump_call,
        "dump_statement": dump_statement,
        "object_expression": dump_call.args[0],
        "scope": scope,
        "loop": loop,
        "protocol": protocol,
        **object_flow,
    }


def _pickle_protocol_loop_shape(loop, load_statement):
    return (
        isinstance(loop, ast.For)
        and load_statement in loop.body
        and isinstance(load_statement, (ast.Assign, ast.AnnAssign, ast.Expr))
        and isinstance(loop.target, ast.Name)
        and not loop.orelse
    )


def _pickle_dump_assignment(
    loop, load_statement, bytes_name, loaded_name, protocol, scope, aliases, audit, node
):
    load_index = loop.body.index(load_statement)
    dumps_name = loaded_name.removesuffix("loads") + "dumps"
    dumps = [
        (statement, statement.value)
        for statement in loop.body[:load_index]
        if _simple_scope_assignment(statement, bytes_name) is not None
        and isinstance(statement.value, ast.Call)
        and audit._normalized_call_name(statement.value, aliases) == dumps_name
    ]
    if len(dumps) != 1:
        return None
    statement, call = dumps[0]
    if not _pickle_dump_shape(call, statement, bytes_name, loop, protocol, scope):
        return None
    if not _pickle_bytes_flow_closed(scope, bytes_name, statement, node):
        return None
    return statement, call


def _pickle_dump_shape(call, statement, bytes_name, loop, protocol, scope):
    target = _pickle_statement_target(statement)
    if not isinstance(target, ast.Name) or target.id != bytes_name:
        return False
    if not isinstance(target.ctx, ast.Store) or len(call.args) != 2 or call.keywords:
        return False
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return False
    use = call.args[1]
    if not (
        isinstance(use, ast.Name)
        and use.id == protocol["name"]
        and not _pickle_protocol_variable_rebound(loop, use)
    ):
        return False
    return not any(
        isinstance(item, (ast.Global, ast.Nonlocal)) and use.id in item.names
        for item in ast.walk(scope)
    )


def _pickle_bytes_flow_closed(scope, name, statement, load_call):
    if any(
        isinstance(item, (ast.Global, ast.Nonlocal)) and name in item.names
        for item in ast.walk(scope)
    ):
        return False
    return _single_local_pickle_bytes_flow(scope, name, statement, load_call)


def _pickle_serializer_imports_closed(
    module,
    scope,
    scope_statement,
    dump_call,
    load_call,
    aliases,
    audit,
    *,
    serializer_namespace_only=False,
):
    index = scope.body.index(scope_statement)
    from .pickle_model_audit import pickle_serializer_imports_closed
    return pickle_serializer_imports_closed(module, scope, index, index, dump_call, load_call, aliases, audit, _pickle_call_imported, _conditional_v3_alias_closure, serializer_namespace_only)


def _closed_pickle_object_flow(scope, loop, loop_statement, dump_call, audit):
    return _closed_pickle_object_flow_at(scope, loop_statement, dump_call, audit)


def _closed_pickle_object_flow_at(scope, boundary_statement, dump_call, audit):
    from .credential_role_constructor_provider import binding_occurrences

    expression = dump_call.args[0]
    if not isinstance(expression, ast.Name) or not isinstance(expression.ctx, ast.Load):
        return None
    name = expression.id
    if name in audit._scope_parameters(scope):
        return None
    initializer = _pickle_object_constructor(scope, name, binding_occurrences)
    if initializer is None:
        return None
    init_index, assignment, constructor, target = initializer
    boundary_index = scope.body.index(boundary_statement)
    if init_index >= boundary_index or not isinstance(constructor, ast.Call):
        return None
    field_flow = _pickle_object_field_writes(scope, name, init_index, boundary_index)
    if field_flow is None:
        return None
    field_writes, field_bases = field_flow
    if not _pickle_object_occurrences_closed(
        scope, name, target, field_bases, expression
    ):
        return None
    return {
        "object_name": name,
        "object_assignment": assignment,
        "constructor_call": constructor,
        "field_writes": tuple(field_writes),
    }


def _pickle_object_constructor(scope, name, binding_occurrences):
    bindings = binding_occurrences(scope.body, name)
    if len(bindings) != 1 or not isinstance(bindings[0], ast.Name):
        return None
    target = bindings[0]
    if not isinstance(target.ctx, ast.Store):
        return None
    for index, statement in enumerate(scope.body):
        value = _simple_scope_assignment(statement, name)
        candidate = _pickle_statement_target(statement)
        if value is not None and candidate is target:
            return index, statement, value, target
    return None


def _pickle_statement_target(statement):
    if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
        return statement.targets[0]
    if isinstance(statement, ast.AnnAssign):
        return statement.target
    return None


def _pickle_object_field_writes(scope, name, init_index, loop_index):
    writes, bases = [], []
    for statement in scope.body[init_index + 1 : loop_index]:
        if isinstance(statement, ast.Pass):
            continue
        base = _pickle_closed_field_write(statement, name)
        if base is None:
            return None
        writes.append(statement)
        bases.append(base)
    return writes, bases


def _pickle_closed_field_write(statement, name):
    if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
        return None
    target = statement.targets[0]
    if (
        not isinstance(target, ast.Attribute)
        or not isinstance(target.ctx, ast.Store)
        or target.attr == "args"
        or target.attr.startswith("__")
    ):
        return None
    base = target.value
    if (
        not isinstance(base, ast.Name)
        or base.id != name
        or not isinstance(base.ctx, ast.Load)
    ):
        return None
    if sum(1 for _ in ast.walk(statement.value)) > 512:
        return None
    return base if _finite_capture._fixed_literal_value(statement.value) else None


def _pickle_object_occurrences_closed(scope, name, target, field_bases, expression):
    if any(
        isinstance(item, (ast.Global, ast.Nonlocal)) and name in item.names
        for item in ast.walk(scope)
    ):
        return False
    occurrences = [
        item
        for item in ast.walk(scope)
        if isinstance(item, ast.Name) and item.id == name
    ]
    allowed = [target, *field_bases, expression]
    return len(occurrences) == len(allowed) and {id(item) for item in occurrences} == {
        id(item) for item in allowed
    }


def _pickle_protocol_variable_rebound(loop, use):
    from .credential_role_constructor_provider import binding_occurrences

    name = use.id
    occurrences = [
        item
        for item in ast.walk(loop)
        if isinstance(item, ast.Name) and item.id == name
    ]
    return (
        binding_occurrences(loop.body, name)
        or len(occurrences) != 2
        or {id(item) for item in occurrences} != {id(loop.target), id(use)}
    )


def _pickle_protocol_loop_range(loop, scope, module, aliases, audit):
    iterator = loop.iter
    if not (
        isinstance(iterator, ast.Call)
        and isinstance(iterator.func, ast.Name)
        and iterator.func.id == "range"
        and not iterator.keywords
        and len(iterator.args) in {1, 2}
    ):
        return None
    if (
        "range" in audit._scope_parameters(scope)
        or any("range" in audit._bound_names(item) for item in scope.body)
        or any(
            item is not scope and "range" in audit._bound_names(item)
            for item in module.body
        )
    ):
        return None
    lower_expr, upper = (
        (ast.Constant(value=0), iterator.args[0])
        if len(iterator.args) == 1
        else iterator.args
    )
    if not _pickle_protocol_integer(lower_expr):
        return None
    lower = ast.literal_eval(lower_expr)
    if isinstance(upper, ast.Constant) and type(upper.value) is int:
        maximum = upper.value - 1
        upper_shape = {"kind": "integer", "stop_exclusive": upper.value}
    elif (
        isinstance(upper, ast.BinOp)
        and isinstance(upper.op, ast.Add)
        and isinstance(upper.right, ast.Constant)
        and type(upper.right.value) is int
        and upper.right.value == 1
        and audit._resolved_ast_name(upper.left, aliases) == "pickle.HIGHEST_PROTOCOL"
    ):
        maximum = "pickle.HIGHEST_PROTOCOL"
        upper_shape = {
            "kind": "provider_constant",
            "stop_exclusive": "pickle.HIGHEST_PROTOCOL + 1",
        }
    else:
        return None
    if lower < 0 or (type(maximum) is int and lower > maximum):
        return None
    return {
        "name": loop.target.id,
        "minimum": lower,
        "maximum": maximum,
        "range": upper_shape,
        "same_iteration": True,
    }


def _plain_scope_statement_index(node, scope):
    """Return a direct function-body position outside uncertain control flow."""
    ancestors = getattr(node, "_oracle_ancestors", ())
    statement = next((child for parent, child in ancestors if parent is scope), None)
    if statement not in scope.body:
        return None
    controls = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.With,
        ast.AsyncWith,
        ast.Match,
        ast.IfExp,
        ast.BoolOp,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
    )
    if any(
        parent is not scope and isinstance(parent, controls) for parent, _ in ancestors
    ):
        return None
    return scope.body.index(statement)


def _simple_scope_assignment(statement, name):
    """Return a value only for one plain-name assignment in this scope."""
    if isinstance(statement, ast.Assign):
        if len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
            return statement.value if statement.targets[0].id == name else None
    if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
        return statement.value if statement.target.id == name else None
    return None


def conditional_provider_pickle_witness(
    profile, source_bytes, source_path, sink_span, audit
):
    """Build source facts for one conditional, trusted-provider pickle roundtrip."""
    try:
        return _conditional_provider_witness(
            profile, source_bytes, source_path, sink_span, audit
        )
    except (
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
        SyntaxError,
        MemoryError,
        RecursionError,
    ):
        return None


def _conditional_provider_witness(profile, source_bytes, source_path, sink_span, audit):
    current = _finite_capture.provider_analysis_profile(
        profile["analysis_profile"], tuple(profile["contracts"])
    )
    if current != profile:
        return None
    if current["analysis_profile"] == "trusted-dependencies-v2":
        return _conditional_provider_v2_witness(
            current, source_bytes, source_path, sink_span, audit
        )
    if current["analysis_profile"] != "trusted-dependencies-v1":
        return None
    contract = current["contracts"][0]
    caller = str(source_path).replace("\\", "/")
    paths = set(contract["artifacts"]) | {caller}
    if not isinstance(source_bytes, dict) or len(paths) > 64:
        return None
    raw = {path: source_bytes[path] for path in paths}
    if any(
        not isinstance(value, bytes) or len(value) > 1_000_000 for value in raw.values()
    ):
        return None
    trees = {path: ast.parse(value) for path, value in raw.items()}
    rows = [(path, list(ast.walk(tree))) for path, tree in trees.items()]
    ast_nodes = sum(len(nodes) for _, nodes in rows)
    if ast_nodes > 100_000 or caller not in trees or not isinstance(sink_span, list):
        return None
    return _conditional_provider_result(
        current,
        contract,
        source_bytes,
        raw,
        trees,
        rows,
        caller,
        sink_span,
        ast_nodes,
        audit,
    )


def _conditional_provider_v2_flow(
    source_bytes, caller, sink_span, audit, *, serializer_namespace_only=False
):
    raw = source_bytes.get(caller)
    if not isinstance(raw, bytes) or len(raw) > 1_000_000:
        return None
    tree = ast.parse(raw)
    modules = {caller: _conditional_module_name(caller)}
    aliases = _conditional_file_aliases(caller, tree, modules)
    if aliases is None:
        return None
    _conditional_provider_parents(tree)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _fixed_program_span(node) == sink_span
    ]
    if len(calls) != 1:
        return None
    node = calls[0]
    return closed_local_pickle_flow(
        node,
        audit._normalized_call_name(node, aliases),
        aliases,
        audit,
        serializer_namespace_only=serializer_namespace_only,
    )


def _conditional_provider_v2_selection(profile, source_bytes, caller, constructor):
    from .runtime_audit_common import canonical_bytes

    selected = []
    for contract in profile["contracts"]:
        digest = hashlib.sha256(canonical_bytes(contract)).hexdigest()
        view = _finite_capture.provider_contract_view(profile, digest)
        binding = _finite_capture.provider_constructor_binding(
            profile,
            source_bytes,
            source_bytes[caller],
            constructor,
            selected_contract_view=view,
        )
        if binding is not None:
            selected.append((view, binding))
    return selected[0] if len(selected) == 1 else None


def _conditional_provider_v2_context(contract, source_bytes, caller):
    paths = set(contract["artifacts"]) | {caller}
    if len(paths) > 64:
        return None
    raw = {path: source_bytes[path] for path in paths}
    if any(
        not isinstance(value, bytes) or len(value) > 1_000_000 for value in raw.values()
    ):
        return None
    trees = {path: ast.parse(value) for path, value in raw.items()}
    rows = [(path, list(ast.walk(tree))) for path, tree in trees.items()]
    ast_nodes = sum(len(nodes) for _, nodes in rows)
    if ast_nodes > 100_000:
        return None
    aliases, classes = _conditional_provider_aliases(trees, contract)
    if aliases is None:
        return None
    return raw, trees, rows, ast_nodes, aliases, classes


def _conditional_provider_v2_witness(
    profile, source_bytes, source_path, sink_span, audit
):
    caller = str(source_path).replace("\\", "/")
    selected = _conditional_selected_pickle_flow(
        profile, source_bytes, caller, sink_span, audit
    )
    if selected is None:
        return None
    flow, view, binding = selected
    if view["contract"]["model"]["id"] == _finite_capture._PROVIDER_MODEL_V4["id"]:
        return _conditional_provider_v4_witness(
            profile, source_bytes, caller, sink_span, flow, view, binding, audit
        )
    if view["contract"]["model"]["id"] == _finite_capture._PROVIDER_MODEL_V3["id"]:
        return _conditional_provider_v3_witness(
            profile, source_bytes, caller, sink_span, flow, view, binding, audit
        )
    context = _conditional_provider_v2_context(view["contract"], source_bytes, caller)
    if context is None:
        return None
    raw, trees, rows, ast_nodes, aliases, classes = context
    classes = _conditional_selected_descendants(rows, aliases, classes, audit)
    initialized = _conditional_initialized_global(
        view["contract"], flow, rows, aliases, classes, audit
    )
    if initialized is None or not _conditional_provider_mutations(
        rows, aliases, classes, audit
    ):
        return None
    record = _finite_capture.provider_exception_record(
        profile,
        raw,
        flow["constructor_call"],
        selected_contract_view=view,
        instance_state={
            write.targets[0].attr: ast.literal_eval(write.value)
            for write in flow["field_writes"]
        },
    )
    if record is None or binding["call_span"] != _fixed_program_span(
        flow["constructor_call"]
    ):
        return None
    facts = _conditional_provider_facts(
        profile,
        view["contract"],
        raw,
        caller,
        sink_span,
        flow,
        binding,
        record,
        ast_nodes,
    )
    if facts is None:
        return None
    return {
        **facts,
        "schema": "factory.conditional-provider-pickle-witness.v2",
        "selected_contract_sha256": view["selected_contract_sha256"],
        "selected_model_sha256": view["selected_model_sha256"],
        "initialized_provider": initialized,
    }


def _conditional_selected_pickle_flow(profile, source_bytes, caller, sink_span, audit):
    if (
        not isinstance(source_bytes, dict)
        or not isinstance(sink_span, list)
        or not _conditional_global_modules_unique(source_bytes)
    ):
        return None
    flow = _conditional_provider_v2_flow(source_bytes, caller, sink_span, audit)
    extended = False
    graph_models = {
        _finite_capture._PROVIDER_MODEL_V3["id"],
        _finite_capture._PROVIDER_MODEL_V4["id"],
    }
    typed = any(item["model"]["id"] in graph_models for item in profile["contracts"])
    if flow is None and typed:
        flow = _conditional_provider_v2_flow(
            source_bytes, caller, sink_span, audit, serializer_namespace_only=True
        )
        extended = flow is not None
    origin = (
        None
        if flow
        else _conditional_provider_v2_direct_origin(
            source_bytes,
            caller,
            sink_span,
            audit,
            serializer_namespace_only=typed,
        )
    )
    constructor = (
        flow["constructor_call"]
        if flow
        else _conditional_pickle_origin_constructor(origin)
        if origin
        else None
    )
    selection = (
        None
        if constructor is None
        else _conditional_provider_v2_selection(
            profile, source_bytes, caller, constructor
        )
    )
    if selection is None:
        return None
    view, binding = selection
    if view["contract"]["model"]["id"] in graph_models:
        flow = _conditional_v3_selected_effect_flow(flow, origin, audit)
    elif extended or origin is not None:
        return None
    return (flow, view, binding) if flow is not None else None


def _conditional_v3_selected_effect_flow(flow, origin, audit):
    if flow is not None:
        return {**flow, "origin_kind": "protocol_loop"}
    return _conditional_pickle_origin_effect_flow(origin, audit)


def _conditional_provider_v4_witness(
    profile, source_bytes, caller, sink_span, flow, view, binding, audit
):
    """Admit only independently regenerated generic source-object graphs."""
    from .pickle_model_audit import provider_native_sources_clear
    if not provider_native_sources_clear(view["contract"], source_bytes):
        return None
    context = _conditional_provider_v2_context(view["contract"], source_bytes, caller)
    if context is None:
        return None
    raw, trees, rows, ast_nodes, aliases, classes = context
    record = _finite_capture.provider_pickle_graph_record(
        profile,
        raw,
        flow["object_expression"],
        selected_contract_view=view,
        source_path=caller,
    )
    if record is None or binding["call_span"] != _fixed_program_span(
        flow["constructor_call"]
    ):
        return None
    active = _conditional_v4_active_nodes(record, flow, caller, trees, aliases, audit)
    if active is None:
        return None
    classes = _conditional_selected_descendants(rows, aliases, classes, audit)
    if record["typed_graph"].get("native_runtime_binding"):
        classes = {*classes, "multidict.CIMultiDict", "multidict.MultiDict",
                   "multidict._multidict.CIMultiDict", "multidict._multidict.MultiDict"}
    if not _conditional_provider_mutations(
        rows,
        aliases,
        classes,
        audit,
        typed_pickle_v3=True,
        active_escape_nodes_by_path=active,
        allowed_reconstruction_hooks=_conditional_v4_hook_nodes(record, trees),
    ):
        return None
    initialized = _conditional_initialized_global(
        view["contract"], flow, rows, aliases, classes, audit
    )
    if initialized is None:
        return None
    return {
        "schema": "factory.conditional-provider-pickle-witness.v4",
        "profile_sha256": profile["profile_sha256"],
        "selected_contract_sha256": view["selected_contract_sha256"],
        "selected_model_sha256": view["selected_model_sha256"],
        "source_path": caller,
        "selected_source_hashes": record["typed_graph"]["source_hashes"],
        "sink_span": sink_span,
        "dump_span": _fixed_program_span(flow["dump_call"]),
        "origin_kind": flow["origin_kind"],
        "initialized_provider": initialized,
        "typed_graph": record["typed_graph"],
        "typed_graph_sha256": record["typed_graph_sha256"],
        "active_frame_span": _fixed_program_span(flow["scope"]),
        "ast_nodes_parsed": ast_nodes,
        "assumptions": list(_finite_capture._PROVIDER_ASSUMPTIONS),
        "target_execution": "not_performed",
        "claim_boundary": "Conditional generic reconstruction under captured provider/runtime identities; not deployment assurance.",
    }


def _conditional_v4_active_nodes(record, flow, caller, trees, aliases, audit):
    active = {path: set() for path in trees}
    for path, tree in trees.items():
        _conditional_v3_add_module_execution_nodes(tree, active[path])
    scope = _conditional_v3_current_node(trees[caller], flow["scope"])
    load = _conditional_v3_current_node(trees[caller], flow["load_call"])
    if scope is None or load is None:
        return None
    active[caller].update(id(node) for node in ast.walk(scope))
    native_calls = frozenset(
        _conditional_span_tuple(node) for node in ast.walk(scope)
        if isinstance(node, ast.Call) and not node.args and not node.keywords
        and audit._resolved_ast_name(node.func, aliases[caller]) == "multidict.CIMultiDict"
    ) if record["typed_graph"].get("native_runtime_binding") else frozenset()
    if not _conditional_v3_frame_calls_closed(
        scope, {**flow, "scope": scope, "load_call": load}, aliases[caller], audit,
        additional_calls=native_calls,
    ):
        return None
    uses = record["typed_graph"]["method_uses"]
    if not isinstance(uses, list) or len(uses) > 512:
        return None
    for use in uses:
        if not _conditional_v4_add_method_use(use, trees, active):
            return None
    return active


def _conditional_v4_add_method_use(use, trees, active):
    method = _conditional_v4_bound_method(use, trees)
    if method is None:
        return False
    active[use["path"]].update(id(node) for node in ast.walk(method))
    return True


def _conditional_v4_bound_method(use, trees):
    if not isinstance(use, dict) or set(use) != {
        "path",
        "class",
        "method",
        "span",
        "ast_sha256",
    }:
        return None
    if use["path"] not in trees:
        return None
    classes = [
        node
        for node in trees[use["path"]].body
        if isinstance(node, ast.ClassDef) and node.name == use["class"]
    ]
    methods = [
        node
        for cls in classes
        for node in cls.body
        if isinstance(node, ast.FunctionDef)
        and node.name == use["method"]
        and _fixed_program_span(node) == use["span"]
        and _conditional_v3_ast_digest(node) == use["ast_sha256"]
    ]
    if len(classes) != 1 or len(methods) != 1:
        return None
    return methods[0]


def _conditional_v4_hook_nodes(record, trees):
    admitted = set()
    hook_names = {"__reduce__", "__getstate__", "__setstate__"}
    for use in record["typed_graph"]["method_uses"]:
        if use.get("method") in hook_names:
            method = _conditional_v4_bound_method(use, trees)
            if method is None:
                raise ValueError("reconstruction hook identity differs")
            admitted.add(id(method))
    return frozenset(admitted)


def _conditional_provider_v2_direct_origin(
    source_bytes,
    caller,
    sink_span,
    audit,
    *,
    serializer_namespace_only=False,
):
    raw = source_bytes.get(caller)
    if not isinstance(raw, bytes) or len(raw) > 1_000_000:
        return None
    tree = ast.parse(raw)
    nodes = list(ast.walk(tree))
    if len(nodes) > 100_000:
        return None
    modules = {caller: _conditional_module_name(caller)}
    aliases = _conditional_file_aliases(caller, tree, modules)
    if aliases is None:
        return None
    _conditional_provider_parents(tree)
    calls = [
        node
        for node in nodes
        if isinstance(node, ast.Call) and _fixed_program_span(node) == sink_span
    ]
    if len(calls) != 1:
        return None
    load_call = calls[0]
    return closed_local_pickle_origin(
        load_call,
        audit._normalized_call_name(load_call, aliases),
        aliases,
        audit,
        serializer_namespace_only=serializer_namespace_only,
    )


def _conditional_pickle_origin_constructor(origin):
    expression = origin["object_expression"]
    if isinstance(expression, ast.Call):
        return expression
    if not isinstance(expression, ast.Name):
        return None
    from .credential_role_constructor_provider import binding_occurrences

    initializer = _pickle_object_constructor(
        origin["scope"], expression.id, binding_occurrences
    )
    if initializer is None or not isinstance(initializer[2], ast.Call):
        return None
    return initializer[2]


def _conditional_pickle_origin_effect_flow(origin, audit):
    expression = origin["object_expression"]
    if isinstance(expression, ast.Name):
        if any(
            isinstance(node, (ast.Global, ast.Nonlocal)) and expression.id in node.names
            for node in ast.walk(origin["scope"])
        ):
            return None
        object_flow = _closed_pickle_object_flow_at(
            origin["scope"], origin["dump_statement"], origin["dump_call"], audit
        )
        if object_flow is None:
            return None
        return {**origin, **object_flow, "loop": None}
    if isinstance(expression, ast.Call):
        return {
            **origin,
            "constructor_call": expression,
            "object_assignment": None,
            "field_writes": (),
            "object_name": None,
            "loop": None,
        }
    return None


def _conditional_provider_v3_witness(
    profile, source_bytes, caller, sink_span, flow, view, binding, audit
):
    context = _conditional_provider_v2_context(view["contract"], source_bytes, caller)
    if context is None:
        return None
    raw, trees, rows, ast_nodes, aliases, classes = context
    classes = _conditional_selected_descendants(rows, aliases, classes, audit)
    export_identities = _conditional_v3_export_identities(view["contract"], raw)
    if export_identities is None:
        return None
    classes.update(export_identities)
    classes = _conditional_selected_descendants(rows, aliases, classes, audit)
    if (
        binding["call_span"] != _fixed_program_span(flow["constructor_call"])
        or _fixed_program_span(flow["constructor_call"])[:2]
        >= _fixed_program_span(flow["dump_call"])[:2]
    ):
        return None
    instance_state = {
        write.targets[0].attr: ast.literal_eval(write.value)
        for write in flow["field_writes"]
    }
    record = _finite_capture.provider_exception_record(
        profile,
        raw,
        flow["object_expression"],
        selected_contract_view=view,
        instance_state=instance_state,
        source_path=caller,
    )
    if record is None:
        return None
    allowed_enum_leaf_nodes = _conditional_v3_enum_leaf_nodes(
        record,
        view["contract"],
        caller,
        flow["constructor_call"],
        raw,
        trees,
        aliases,
        audit,
    )
    if allowed_enum_leaf_nodes is None:
        return None
    active_escape_nodes = _conditional_v3_active_escape_nodes(
        flow, record, view["contract"], caller, trees, aliases, audit
    )
    if active_escape_nodes is None:
        return None
    if not _conditional_provider_mutations(
        rows,
        aliases,
        classes,
        audit,
        allowed_enum_leaf_nodes=allowed_enum_leaf_nodes,
        typed_pickle_v3=True,
        active_escape_nodes_by_path=active_escape_nodes,
    ):
        return None
    initialized = _conditional_initialized_global(
        view["contract"], flow, rows, aliases, classes, audit
    )
    if initialized is None:
        return None
    facts = _conditional_provider_facts(
        profile,
        view["contract"],
        raw,
        caller,
        sink_span,
        flow,
        binding,
        record,
        ast_nodes,
        allow_missing_object_assignment=True,
    )
    if facts is None:
        return None
    return {
        **facts,
        "schema": "factory.conditional-provider-pickle-witness.v2",
        "selected_contract_sha256": view["selected_contract_sha256"],
        "selected_model_sha256": view["selected_model_sha256"],
        "initialized_provider": initialized,
        "typed_graph_sha256": record["typed_graph_sha256"],
        "active_frame": {
            "source_path": caller,
            "span": _fixed_program_span(flow["scope"]),
            "ast_sha256": hashlib.sha256(
                ast.dump(flow["scope"], include_attributes=False).encode()
            ).hexdigest(),
            "origin_kind": flow["origin_kind"],
            "modeled_methods": [
                *record["initializer_uses"],
                *record["display_method_uses"],
            ],
            "global_counterevidence": "explicit captured provider and registry writes remain rejected",
            "deferred_bodies": "potential escapes only; conditional immutable initialized provider",
        },
    }


def _conditional_v3_active_escape_nodes(
    flow, record, contract, caller, trees, aliases_by_path, audit
):
    """Bind active AST identities to the exact current parse, never another tree."""
    active = {path: set() for path in trees}
    for path, tree in trees.items():
        _conditional_v3_add_module_execution_nodes(tree, active[path])
    caller_tree = trees.get(caller)
    if not isinstance(caller_tree, ast.Module):
        return None
    _conditional_provider_parents(caller_tree)
    scope = _conditional_v3_current_node(caller_tree, flow["scope"])
    load = _conditional_v3_current_node(caller_tree, flow["load_call"])
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) or load is None:
        return None
    flow = {**flow, "scope": scope, "load_call": load}
    active[caller].update(id(node) for node in ast.walk(scope))
    if not _conditional_v3_activate_bound_methods(record, contract, trees, active):
        return None
    aliases = aliases_by_path[caller]
    if not _conditional_v3_display_scope_closed(
        scope, flow, record, caller_tree, aliases, audit
    ):
        return None
    return (
        active
        if _conditional_v3_frame_calls_closed(scope, flow, aliases, audit)
        else None
    )


def _conditional_v3_activate_bound_methods(record, contract, trees, active):
    initializers, displays = (
        record.get("initializer_uses"),
        record.get("display_method_uses", []),
    )
    if not isinstance(initializers, list) or len(initializers) != 1:
        return False
    if not isinstance(displays, list) or len(displays) > 8:
        return False
    for use, expected in [
        (initializers[0], "__init__"),
        *((item, "__str__") for item in displays),
    ]:
        method = _conditional_v3_bound_method(use, expected, contract, trees)
        if method is None:
            return False
        active[use["source_path"]].update(id(node) for node in ast.walk(method))
    return True


def _conditional_v3_bound_method(use, expected, contract, trees):
    base = {
        "source_path",
        "class_name",
        "class_ast_sha256",
        "method_name",
        "span",
        "ast_sha256",
    }
    extra = (
        {"recipe", "cast_import_span", "cast_import_ast_sha256"}
        if expected == "__str__"
        else set()
    )
    if (
        not isinstance(use, dict)
        or set(use) != base | extra
        or use["method_name"] != expected
    ):
        return None
    if extra and use["recipe"] != "TYPING_CAST_IDENTITY_ARGS_INDEX_1":
        return None
    path = use["source_path"]
    if path not in trees or path not in contract["artifacts"]:
        return None
    rows = [
        row
        for row in contract["classes"]
        if (row["path"], row["name"], row["class_ast_sha256"])
        == (path, use["class_name"], use["class_ast_sha256"])
    ]
    classes = [
        node
        for node in trees[path].body
        if isinstance(node, ast.ClassDef)
        and node.name == use["class_name"]
        and _conditional_v3_ast_digest(node) == use["class_ast_sha256"]
    ]
    if len(rows) != 1 or len(classes) != 1:
        return None
    methods = [
        node
        for node in classes[0].body
        if isinstance(node, ast.FunctionDef)
        and node.name == expected
        and _fixed_program_span(node) == use["span"]
        and _conditional_v3_ast_digest(node) == use["ast_sha256"]
    ]
    return methods[0] if len(methods) == 1 else None


def _conditional_v3_ast_digest(node):
    return hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()


def _conditional_v3_display_scope_closed(scope, flow, record, module, aliases, audit):
    calls = [
        node
        for node in ast.walk(scope)
        if isinstance(node, ast.Call)
        and audit._resolved_ast_name(node.func, aliases) == "str"
    ]
    if not calls:
        return True
    shadowed = "str" in audit._scope_parameters(scope) or any(
        "str" in audit._bound_names(statement)
        for statement in [*module.body, *scope.body]
    )
    loaded = _conditional_v3_load_target_name(flow["load_call"])
    return (
        not shadowed
        and len(record.get("display_method_uses", [])) == 1
        and all(
            _conditional_v3_display_call_shape(call, loaded, aliases, audit)
            and _fixed_program_span(call)[:2]
            > _fixed_program_span(flow["load_call"])[:2]
            for call in calls
        )
    )


def _conditional_v3_current_node(tree, original):
    matches = [
        node
        for node in ast.walk(tree)
        if type(node) is type(original)
        and _fixed_program_span(node) == _fixed_program_span(original)
        and ast.dump(node, include_attributes=False)
        == ast.dump(original, include_attributes=False)
    ]
    return matches[0] if len(matches) == 1 else None


def _conditional_v3_frame_calls_closed(scope, flow, aliases, audit, *, additional_calls=frozenset()):
    """Unknown active callbacks cannot inherit the deferred-body exception."""
    if any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
        and node is not scope
        for node in ast.walk(scope)
    ):
        return False
    approved = {
        _conditional_span_tuple(flow[key])
        for key in ("constructor_call", "dump_call", "load_call")
    }
    approved.update(additional_calls)
    loop = flow.get("loop")
    if isinstance(loop, ast.For):
        approved.add(_conditional_span_tuple(loop.iter))
    loaded_name = _conditional_v3_load_target_name(flow["load_call"])
    return all(
        _conditional_span_tuple(node) in approved
        or _conditional_v3_display_call_shape(node, loaded_name, aliases, audit)
        for node in ast.walk(scope)
        if isinstance(node, ast.Call)
    )


def _conditional_span_tuple(node):
    return tuple(_fixed_program_span(node))


def _conditional_v3_display_call_shape(node, loaded_name, aliases, audit):
    return (
        loaded_name is not None
        and audit._resolved_ast_name(node.func, aliases) == "str"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == loaded_name
    )


def _conditional_v3_load_statement(load_call, scope):
    node = load_call
    while node is not None and node is not scope:
        parent = getattr(node, "_security_parent", None)
        if parent is scope:
            return node
        node = parent
    return None


def _conditional_v3_load_target_name(load_call):
    parent = getattr(load_call, "_security_parent", None)
    if (
        isinstance(parent, ast.Assign)
        and parent.value is load_call
        and len(parent.targets) == 1
    ):
        return parent.targets[0].id if isinstance(parent.targets[0], ast.Name) else None
    if isinstance(parent, ast.AnnAssign) and parent.value is load_call:
        return parent.target.id if isinstance(parent.target, ast.Name) else None
    return None


def _conditional_v3_add_module_execution_nodes(node, active):
    """Mark import-time syntax while excluding deferred function and lambda bodies."""
    active.add(id(node))
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for field, value in ast.iter_fields(node):
            if field != "body":
                _conditional_v3_add_module_execution_value(value, active)
        return
    if isinstance(node, ast.Lambda):
        for field, value in ast.iter_fields(node):
            if field != "body":
                _conditional_v3_add_module_execution_value(value, active)
        return
    for child in ast.iter_child_nodes(node):
        _conditional_v3_add_module_execution_nodes(child, active)


def _conditional_v3_add_module_execution_value(value, active):
    if isinstance(value, ast.AST):
        _conditional_v3_add_module_execution_nodes(value, active)
    elif isinstance(value, list):
        for item in value:
            _conditional_v3_add_module_execution_value(item, active)


def _conditional_v3_export_identities(contract, source_bytes):
    identities = set()
    for class_row in contract["classes"]:
        chain = _finite_capture.provider_export_chain_v3(
            contract, source_bytes, class_row=class_row
        )
        if not isinstance(chain, list) or not chain:
            return None
        for item in chain:
            module, symbol = item.get("module"), item.get("symbol")
            if (
                not isinstance(module, str)
                or not module
                or not isinstance(symbol, str)
                or not symbol.isidentifier()
            ):
                return None
            identities.add(f"{module}.{symbol}")
    return identities


def _conditional_global_modules_unique(source_bytes):
    """A source path cannot stand in for two competing Python module identities."""
    modules = set()
    for path in source_bytes:
        if not isinstance(path, str):
            return False
        if not path.endswith(".py"):
            continue
        name = _conditional_module_name(path).casefold()
        if name in modules:
            return False
        modules.add(name)
    return True


def _conditional_initialized_global(contract, flow, rows, aliases, classes, audit):
    """Conditional cached lookup implication; never inspect target runtime state."""
    for path, nodes in rows:
        if any(
            _conditional_global_lookup_hazard(node, aliases[path], audit)
            for node in nodes
        ):
            return None
    first = contract["classes"][0]
    module = _conditional_module_name(first["path"])
    if not module or not first["name"].isidentifier():
        return None
    if (
        _fixed_program_span(flow["constructor_call"])[:2]
        >= _fixed_program_span(flow["dump_call"])[:2]
    ):
        return None
    return {
        "schema": "factory.initialized-pickle-global.v1",
        "status": "CONDITIONAL_CACHED_GLOBAL_IDENTITY",
        "module": module,
        "qualname": first["name"],
        "export": dict(contract["export"]),
        "class_ast_sha256": first["class_ast_sha256"],
        "constructor_span": _fixed_program_span(flow["constructor_call"]),
        "successful_dump_span": _fixed_program_span(flow["dump_call"]),
        "load_span": _fixed_program_span(flow["load_call"]),
        "identity_check": "canonical_save_global_then_cached_find_class",
        "initialization_safety": "TRUSTED_NOT_AUDITED",
        "initialization_premise": "declared trusted initialization completed before constructor binding",
        "audit_event": "pickle.find_class; source-visible hook registration rejected",
        "runtime_observation": "not_performed",
    }


def _conditional_global_lookup_hazard(node, aliases, audit):
    name = audit._resolved_ast_name(node, aliases)
    if name.startswith(
        (
            "sys.modules",
            "sys.meta_path",
            "sys.path_hooks",
            "sys.path_importer_cache",
            "copyreg._extension_registry",
            "copyreg._inverted_registry",
            "copyreg._extension_cache",
            "pickle._extension_registry",
            "pickle._inverted_registry",
            "pickle._extension_cache",
            "copyreg.dispatch_table",
            "pickle.dispatch_table",
            "pickle.Pickler.dispatch_table",
        )
    ):
        return True
    if name in {
        "builtins.__import__",
        "__builtins__.__import__",
        "builtins.globals",
        "builtins.locals",
        "builtins.vars",
        "builtins.eval",
        "builtins.exec",
    }:
        return True
    if isinstance(node, ast.Name) and node.id in {
        "__builtins__",
        "__import__",
        "globals",
        "locals",
        "vars",
        "eval",
        "exec",
    }:
        return True
    if _conditional_reflection_alias_hazard(node, name):
        return True
    if _conditional_lookup_import_hazard(node):
        return True
    if isinstance(node, ast.Call):
        return _conditional_lookup_call_hazard(node, aliases, audit)
    if isinstance(node, ast.Attribute) and node.attr in {
        "persistent_id",
        "persistent_load",
        "find_class",
        "__module__",
        "__qualname__",
        "__bases__",
        "__mro__",
    }:
        return isinstance(node.ctx, (ast.Store, ast.Del))
    return False


def _conditional_lookup_call_hazard(node, aliases, audit):
    call = audit._resolved_ast_name(node.func, aliases)
    if _conditional_dynamic_namespace_call(node, call, aliases, audit):
        return True
    if call in {
        "sys.addaudithook",
        "importlib.reload",
        "builtins.reload",
        "copyreg.add_extension",
        "copyreg.remove_extension",
        "copyreg.clear_extension_cache",
    }:
        return True
    return call.startswith(
        (
            "copyreg._extension",
            "copyreg._inverted_registry",
            "pickle.Unpickler",
            "_pickle.Unpickler",
        )
    )


def _conditional_lookup_import_hazard(node):
    if not isinstance(node, ast.ImportFrom) or node.module not in {
        "sys",
        "importlib",
        "copyreg",
        "builtins",
    }:
        return False
    sensitive = {
        "addaudithook",
        "modules",
        "meta_path",
        "path_hooks",
        "reload",
        "add_extension",
        "remove_extension",
        "clear_extension_cache",
        "_extension_registry",
        "_inverted_registry",
        "_extension_cache",
        "dispatch_table",
        "globals",
        "locals",
        "vars",
        "eval",
        "exec",
        "__import__",
        "getattr",
        "setattr",
        "delattr",
    }
    return any(item.name in sensitive for item in node.names)


def _conditional_reflection_alias_hazard(node, name):
    capabilities = {
        "getattr",
        "setattr",
        "delattr",
        "builtins.getattr",
        "builtins.setattr",
        "builtins.delattr",
    }
    if name not in capabilities or not isinstance(node, (ast.Name, ast.Attribute)):
        return False
    parent = getattr(node, "_security_parent", None)
    return not (isinstance(parent, ast.Call) and parent.func is node)


def _conditional_dynamic_namespace_call(node, call, aliases, audit):
    if call in {
        "globals",
        "locals",
        "vars",
        "eval",
        "exec",
        "builtins.globals",
        "builtins.locals",
        "builtins.vars",
        "builtins.eval",
        "builtins.exec",
    }:
        return True
    if (
        call
        not in {
            "getattr",
            "setattr",
            "delattr",
            "builtins.getattr",
            "builtins.setattr",
            "builtins.delattr",
        }
        or not node.args
    ):
        return False
    target = audit._resolved_ast_name(node.args[0], aliases)
    return target in {"sys", "copyreg", "pickle", "builtins", "__builtins__"}


def _conditional_selected_descendants(rows, aliases, classes, audit):
    """Include method/descriptor owners so their code cannot drift under a stable type."""
    selected = set(classes)
    prefixes = tuple(name + "." for name in classes)
    for path, nodes in rows:
        for node in nodes:
            name = audit._resolved_ast_name(node, aliases[path])
            if name.startswith(prefixes):
                selected.add(name)
    return selected


def _conditional_provider_result(
    current,
    contract,
    source_bytes,
    raw,
    trees,
    rows,
    caller,
    sink_span,
    ast_nodes,
    audit,
):
    aliases, classes = _conditional_provider_aliases(trees, contract)
    if aliases is None:
        return None
    _conditional_provider_parents(trees[caller])
    calls = [
        node
        for node in ast.walk(trees[caller])
        if isinstance(node, ast.Call) and _fixed_program_span(node) == sink_span
    ]
    if len(calls) != 1:
        return None
    load = calls[0]
    flow = closed_local_pickle_flow(
        load, audit._normalized_call_name(load, aliases[caller]), aliases[caller], audit
    )
    if flow is None:
        return None
    constructor = flow["constructor_call"]
    binding = _finite_capture.provider_constructor_binding(
        current, source_bytes, raw[caller], constructor
    )
    record = _finite_capture.provider_exception_record(current, raw, constructor)
    if (
        binding is None
        or record is None
        or binding["call_span"] != _fixed_program_span(constructor)
        or binding["export"] != contract["export"]
    ):
        return None
    if not _conditional_provider_mutations(rows, aliases, classes, audit):
        return None
    return _conditional_provider_facts(
        current, contract, raw, caller, sink_span, flow, binding, record, ast_nodes
    )


def _conditional_provider_facts(
    current,
    contract,
    raw,
    caller,
    sink_span,
    flow,
    binding,
    record,
    ast_nodes,
    *,
    allow_missing_object_assignment=False,
):
    if not allow_missing_object_assignment and "object_assignment" not in flow:
        return None
    hashes = {
        path: hashlib.sha256(value).hexdigest() for path, value in sorted(raw.items())
    }
    field_rows = [
        {
            "span": _fixed_program_span(write),
            "value_sha256": hashlib.sha256(
                ast.dump(write.value, include_attributes=False).encode()
            ).hexdigest(),
        }
        for write in flow["field_writes"]
    ]
    state_hash = hashlib.sha256(
        repr((record["args"], sorted(record["state"].items()))).encode()
    ).hexdigest()
    states = len(hashes) + len(contract["classes"]) + len(field_rows) + 6 + len(raw)
    if states > 512:
        return None
    facts = {
        "schema": "factory.conditional-provider-pickle-witness.v1",
        "analysis_profile": current["analysis_profile"],
        "profile_sha256": current["profile_sha256"],
        "model_sha256": current["model_sha256"],
        "contract_sha256": current["contract_sha256"],
        "runtime_identity_sha256": hashlib.sha256(
            repr(sorted(contract["runtime"].items())).encode()
        ).hexdigest(),
        "source_path": caller,
        "caller_sha256": hashes[caller],
        "selected_source_hashes": hashes,
        "export": dict(binding["export"]),
        "sink_span": sink_span,
        "constructor_span": binding["call_span"],
        "object_assignment_span": _fixed_program_span(flow.get("object_assignment")),
        "dump_span": _fixed_program_span(flow["dump_call"]),
        "load_span": _fixed_program_span(flow["load_call"]),
        "protocol": dict(flow["protocol"]),
        "field_writes": field_rows,
        "constructor_state_sha256": state_hash,
        "evidence_source_count": len(hashes),
        "evidence_bytes": sum(map(len, raw.values())),
        "evidence_states": states,
        "ast_nodes_parsed": ast_nodes,
        "assumptions": list(_finite_capture._PROVIDER_ASSUMPTIONS),
        "source_scope": "contract artifacts plus caller source only",
        "target_execution": "not_performed",
    }
    if allow_missing_object_assignment:
        facts["object_origin_kind"] = flow.get("origin_kind", "unknown")
        facts["enum_leaf_uses"] = list(record.get("enum_leaf_uses", []))
    return facts


def _conditional_provider_aliases(trees, contract):
    modules = {path: _conditional_module_name(path) for path in trees}
    aliases = {
        path: _conditional_file_aliases(path, tree, modules)
        for path, tree in trees.items()
    }
    if any(mapping is None for mapping in aliases.values()):
        return None, None
    class_paths = {
        f"{modules[row['path']]}.{row['name']}" for row in contract["classes"]
    }
    for row in contract["classes"]:
        aliases[row["path"]][row["name"]] = f"{modules[row['path']]}.{row['name']}"
    originals = set(class_paths)
    if contract["model"]["id"] == _finite_capture._PROVIDER_MODEL_V3["id"]:
        changed = True
        while changed:
            changed = False
            for path, mapping in aliases.items():
                for name, target in mapping.items():
                    alias_path = f"{modules[path]}.{name}"
                    if target in class_paths and alias_path not in class_paths:
                        class_paths.add(alias_path)
                        changed = True
    else:
        for path, mapping in aliases.items():
            class_paths.update(
                f"{modules[path]}.{name}"
                for name, target in mapping.items()
                if target in originals
            )
    return aliases, class_paths


def _conditional_file_aliases(path, tree, modules):
    module = modules[path]
    package = module if path.endswith("/__init__.py") else module.rpartition(".")[0]
    aliases = {}
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for item in statement.names:
                aliases[item.asname or item.name.split(".")[0]] = (
                    item.name if item.asname else item.name.split(".")[0]
                )
        elif isinstance(statement, ast.ImportFrom):
            base = _conditional_relative_module(
                package, statement.level, statement.module
            )
            if base is None or any(item.name == "*" for item in statement.names):
                return None
            for item in statement.names:
                target = f"{base}.{item.name}" if base else item.name
                aliases[item.asname or item.name] = target
    return aliases


def _conditional_relative_module(package, level, module):
    if level == 0:
        return module
    parts = package.split(".") if package else []
    if level > len(parts) + 1:
        return None
    return ".".join(
        [*parts[: len(parts) - level + 1], *(module.split(".") if module else [])]
    )


def _conditional_provider_parents(tree):
    pending = [(tree, None, None)]
    while pending:
        node, parent, scope = pending.pop()
        if parent is not None:
            node._security_parent = parent
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            scope = node
            node._security_parent_scope = getattr(
                parent, "_security_parent_scope", tree
            )
        if isinstance(node, ast.Module):
            node._oracle_module = tree
        elif scope is not None:
            node._security_lexical_scope = scope
            node._oracle_scope = scope
            node._oracle_module = tree
        pending.extend((child, node, scope) for child in ast.iter_child_nodes(node))


def _conditional_provider_mutations(
    node_rows,
    aliases_by_path,
    selected_classes,
    audit,
    *,
    allowed_enum_leaf_nodes=frozenset(),
    typed_pickle_v3=False,
    active_escape_nodes_by_path=None,
    allowed_reconstruction_hooks=frozenset(),
):
    module_exports = _conditional_module_exports(selected_classes)
    for path, nodes in node_rows:
        aliases = aliases_by_path[path]
        if typed_pickle_v3:
            aliases = _conditional_v3_alias_closure(
                nodes, aliases, selected_classes, audit
            )
        active_escape_nodes = (active_escape_nodes_by_path or {}).get(path, set())
        parents = {
            id(child): node for node in nodes for child in ast.iter_child_nodes(node)
        }
        if typed_pickle_v3 and _conditional_enum_base_mutated(nodes, aliases, audit):
            return False
        fact_nodes = [
            node
            for node in nodes
            if id(node) not in allowed_enum_leaf_nodes
            and (
                not typed_pickle_v3
                or id(node) in active_escape_nodes
                or _conditional_v3_explicit_mutation_fact(
                    node, aliases, selected_classes, module_exports, audit
                )
            )
        ]

        def capture_predicate(statement):
            return (
                not typed_pickle_v3
                or id(statement) in active_escape_nodes
                or _conditional_v3_global_capture(statement, parents)
            )

        facts = _finite_capture.finite_provider_mutation_index(
            fact_nodes,
            aliases,
            audit,
            parents,
            capture_predicate=capture_predicate,
        )
        registry_roots = (
            "copyreg.dispatch_table",
            "pickle.dispatch_table",
            "pickle.Pickler.dispatch_table",
        )
        if any(
            owner in selected_classes
            or owner == "copyreg"
            or owner.startswith(registry_roots)
            for owner, _ in facts
        ):
            return False
        if any(
            not _conditional_provider_node_safe(
                node,
                path,
                aliases,
                selected_classes,
                module_exports,
                audit,
                allowed_enum_leaf_nodes=allowed_enum_leaf_nodes,
                active_escape_nodes=active_escape_nodes if typed_pickle_v3 else None,
                allowed_reconstruction_hooks=allowed_reconstruction_hooks,
            )
            for node in nodes
        ):
            return False
    return True


def _conditional_v3_alias_closure(nodes, aliases, selected_classes, audit):
    """Keep class, method and enum-member write aliases visible even in deferred bodies."""
    resolved = dict(aliases)
    for _ in range(8):
        previous = dict(resolved)
        for node in nodes:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = getattr(node, "value", None)
            if not isinstance(value, (ast.Name, ast.Attribute)):
                continue
            origin = audit._resolved_ast_name(value, resolved)
            if not any(
                origin == selected or origin.startswith(selected + ".")
                for selected in selected_classes
            ):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            resolved.update(
                {
                    target.id: origin
                    for target in targets
                    if isinstance(target, ast.Name)
                }
            )
        if resolved == previous:
            return resolved
    # A chain beyond the bound must not hide a write through its last alias.
    raise ValueError("provider alias closure exceeds eight steps")


def _conditional_v3_explicit_mutation_fact(
    node, aliases, selected_classes, module_exports, audit
):
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return True
    if not isinstance(node, ast.Call):
        return False
    callee = audit._resolved_ast_name(node.func, aliases)
    if callee in {
        "copyreg.pickle",
        "copyreg.add_extension",
        "copyreg.remove_extension",
        "copyreg.clear_extension_cache",
        "pickle.Pickler.dispatch_table.update",
        "copyreg.dispatch_table.update",
        "sys.addaudithook",
        "importlib.reload",
        "builtins.reload",
    }:
        return True
    if _conditional_module_export_write(node, aliases, module_exports, audit):
        return True
    if _conditional_module_dict_update(node, aliases, module_exports, audit):
        return True
    if callee in {"setattr", "delattr", "builtins.setattr", "builtins.delattr"}:
        return bool(
            node.args
            and _conditional_selected_reference(
                node.args[0], aliases, audit, selected_classes, module_exports
            )
        )
    return False


def _conditional_v3_global_capture(statement, parents):
    if not isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
        return False
    targets = (
        statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    )
    names = {
        node.id
        for target in targets
        for node in ast.walk(target)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }
    if not names:
        return False
    current = statement
    while current is not None and not isinstance(
        current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
    ):
        current = parents.get(id(current))
    if current is None:
        return False
    return any(
        isinstance(node, (ast.Global, ast.Nonlocal))
        and bool(names.intersection(node.names))
        for node in ast.walk(current)
    )


def _conditional_provider_node_safe(
    node,
    path,
    aliases,
    selected_classes,
    module_exports,
    audit,
    *,
    allowed_enum_leaf_nodes=frozenset(),
    active_escape_nodes=None,
    allowed_reconstruction_hooks=frozenset(),
):
    hooks = {
        "__reduce__",
        "__reduce_ex__",
        "__getstate__",
        "__setstate__",
        "__getattribute__",
        "__setattr__",
        "__init_subclass__",
    }
    if (
        isinstance(node, ast.ClassDef)
        and f"{_conditional_module_name(path)}.{node.name}" in selected_classes
    ):
        if any(
            isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name in hooks
            and id(item) not in allowed_reconstruction_hooks
            for item in node.body
        ):
            return False
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
        targets = (
            node.targets
            if isinstance(node, (ast.Assign, ast.Delete))
            else [node.target]
        )
        if any(
            _conditional_selected_reference(
                target, aliases, audit, selected_classes, module_exports
            )
            for target in targets
        ):
            return False
        value = getattr(node, "value", None)
        if (
            (active_escape_nodes is None or id(node) in active_escape_nodes)
            and value is not None
            and _conditional_selected_reference(
                value, aliases, audit, selected_classes, module_exports
            )
        ):
            return False
        if any(
            _conditional_registry_path(target, audit, aliases) for target in targets
        ):
            return False
    if (
        isinstance(node, ast.Call)
        and (
            active_escape_nodes is None
            or id(node) in active_escape_nodes
            or _conditional_v3_explicit_mutation_fact(
                node, aliases, selected_classes, module_exports, audit
            )
        )
        and not _conditional_provider_call_safe(
            node,
            aliases,
            selected_classes,
            module_exports,
            audit,
            allowed_enum_leaf_nodes=allowed_enum_leaf_nodes,
        )
    ):
        return False
    return not (
        (active_escape_nodes is None or id(node) in active_escape_nodes)
        and isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom))
        and _conditional_selected_reference(
            node.value, aliases, audit, selected_classes, module_exports
        )
    )


def _conditional_provider_call_safe(
    node,
    aliases,
    selected_classes,
    module_exports,
    audit,
    *,
    allowed_enum_leaf_nodes=frozenset(),
):
    callee = audit._resolved_ast_name(node.func, aliases)
    registry = {
        "copyreg.pickle",
        "copyreg.add_extension",
        "pickle.Pickler.dispatch_table.update",
        "copyreg.dispatch_table.update",
    }
    if callee in registry or callee in {"__import__", "importlib.import_module"}:
        return False
    if _conditional_module_export_write(
        node, aliases, module_exports, audit
    ) or _conditional_module_dict_update(node, aliases, module_exports, audit):
        return False
    for argument in [*node.args, *(item.value for item in node.keywords)]:
        if id(argument) in allowed_enum_leaf_nodes:
            continue
        if _conditional_selected_reference(
            argument, aliases, audit, selected_classes, module_exports
        ):
            return False
    return True


def _conditional_enum_base_mutated(
    nodes, aliases, audit, *, additional_roots=frozenset()
):
    """Canonical base writes and their aliases remain global counterevidence."""
    roots = {
        "enum.Enum",
        "enum.IntEnum",
        "enum.EnumType",
        "enum.EnumMeta",
        "Exception",
        "BaseException",
        "builtins.Exception",
        "builtins.BaseException",
    }
    roots.update(additional_roots)
    aliases = _conditional_v3_alias_closure(nodes, aliases, roots, audit)
    for node in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            targets = (
                node.targets
                if isinstance(node, (ast.Assign, ast.Delete))
                else [node.target]
            )
            value = getattr(node, "value", None)
            # Creating a fresh name for a canonical descriptor does not write
            # through it. Keep subsequent writes via that alias visible.
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(
                value, (ast.Name, ast.Attribute)
            ) and _conditional_enum_root_path(value, aliases, roots, audit):
                targets = [target for target in targets
                           if not isinstance(target, ast.Name) or target.id in roots]
            if any(
                _conditional_enum_root_path(target, aliases, roots, audit)
                for target in targets
            ):
                return True
        if _conditional_enum_base_call_mutated(node, aliases, roots, audit):
            return True
    return False


def _conditional_enum_root_path(node, aliases, roots, audit):
    name = audit._resolved_ast_name(node, aliases)
    return any(name == root or name.startswith(root + ".") for root in roots)


def _conditional_enum_base_call_mutated(node, aliases, roots, audit):
    if not isinstance(node, ast.Call):
        return False
    callee = audit._resolved_ast_name(node.func, aliases)
    if (
        callee in {"setattr", "delattr", "builtins.setattr", "builtins.delattr"}
        and node.args
    ):
        return _conditional_enum_root_path(node.args[0], aliases, roots, audit)
    return isinstance(node.func, ast.Attribute) and _conditional_enum_root_path(
        node.func.value, aliases, roots, audit
    )


def _conditional_v3_enum_leaf_nodes(
    record, contract, caller, constructor_call, raw, trees, aliases_by_path, audit
):
    """Match only regenerated typed leaves inside the selected constructor."""
    rows = record.get("enum_leaf_uses", [])
    if not isinstance(rows, list) or len(rows) > 512:
        return None
    if not rows:
        return frozenset()
    tree, aliases = trees.get(caller), aliases_by_path.get(caller)
    if not isinstance(tree, ast.Module) or not isinstance(aliases, dict):
        return None
    call = _conditional_v3_current_node(tree, constructor_call)
    if call is None:
        return None
    argument_nodes = {
        id(node)
        for root in [*call.args, *(item.value for item in call.keywords)]
        for node in ast.walk(root)
    }
    classes = {(item["path"], item["name"]): item for item in contract["classes"]}
    allowed, seen = set(), set()
    for row in rows:
        if not _conditional_v3_enum_row_shape(row, caller):
            return None
        identity = (tuple(row["span"]), row["ast_sha256"])
        leaf = _conditional_v3_enum_leaf(
            row, classes, tree, aliases, argument_nodes, contract, raw, audit
        )
        if identity in seen or leaf is None:
            return None
        seen.add(identity)
        allowed.update(id(node) for node in ast.walk(leaf))
    return frozenset(allowed)


def _conditional_v3_enum_row_shape(row, caller):
    required = {
        "source_path",
        "span",
        "ast_sha256",
        "enum_class_path",
        "enum_class_name",
        "class_ast_sha256",
        "member",
        "literal_value",
    }
    return (
        isinstance(row, dict)
        and set(row) == required
        and row["source_path"] == caller
        and isinstance(row["span"], list)
        and len(row["span"]) == 4
        and all(type(value) is int for value in row["span"])
        and all(
            isinstance(row[key], str)
            for key in (
                "ast_sha256",
                "enum_class_path",
                "enum_class_name",
                "class_ast_sha256",
                "member",
            )
        )
        and type(row["literal_value"]) is int
    )


def _conditional_v3_enum_leaf(
    row, classes, tree, aliases, argument_nodes, contract, raw, audit
):
    enum = classes.get((row["enum_class_path"], row["enum_class_name"]))
    if enum is None or enum["class_ast_sha256"] != row["class_ast_sha256"]:
        return None
    matches = [
        node
        for node in ast.walk(tree)
        if _fixed_program_span(node) == row["span"]
        and _conditional_v3_ast_digest(node) == row["ast_sha256"]
    ]
    if len(matches) != 1:
        return None
    leaf = matches[0]
    if (
        not isinstance(leaf, (ast.Name, ast.Attribute))
        or not isinstance(leaf.ctx, ast.Load)
        or id(leaf) not in argument_nodes
    ):
        return None
    chain = _finite_capture.provider_export_chain_v3(contract, raw, class_row=enum)
    if not isinstance(chain, list) or not chain:
        return None
    paths = {
        item["module"] + "." + item["symbol"] + "." + row["member"] for item in chain
    }
    paths.add(
        _conditional_module_name(row["enum_class_path"])
        + "."
        + row["enum_class_name"]
        + "."
        + row["member"]
    )
    return leaf if audit._resolved_ast_name(leaf, aliases) in paths else None


def _conditional_resolved_name(node, aliases, audit):
    return audit._resolved_ast_name(node, aliases)


def _conditional_module_exports(selected_classes):
    exports = {}
    for path in selected_classes:
        module, _, name = path.rpartition(".")
        exports.setdefault(module, set()).add(name)
    return exports


def _conditional_module_export_write(call, aliases, module_exports, audit):
    name = audit._resolved_ast_name(call.func, aliases)
    if (
        name not in {"setattr", "delattr", "builtins.setattr", "builtins.delattr"}
        or not call.args
    ):
        return False
    module = audit._resolved_ast_name(call.args[0], aliases)
    if module not in module_exports:
        return False
    if (
        len(call.args) < 2
        or not isinstance(call.args[1], ast.Constant)
        or type(call.args[1].value) is not str
    ):
        return True
    return call.args[1].value in module_exports[module]


def _conditional_selected_reference(
    node, aliases, audit, selected_classes, module_exports
):
    if _conditional_selected_path(node, aliases, audit, selected_classes) or (
        isinstance(node, ast.Name) and audit._resolved_ast_name(node, aliases) in module_exports
    ):
        return True
    if isinstance(node, ast.Subscript):
        if _conditional_module_dict(node.value, aliases, audit, module_exports):
            key = node.slice
            if not isinstance(key, ast.Constant) or type(key.value) is not str:
                return True
            module = _conditional_module_dict_path(node.value, aliases, audit)
            return key.value in module_exports.get(module, set())
    if (
        isinstance(node, ast.Call)
        and audit._resolved_ast_name(node.func, aliases) == "getattr"
        and len(node.args) >= 2
    ):
        module = audit._resolved_ast_name(node.args[0], aliases)
        if module in module_exports:
            key = node.args[1]
            return (
                not isinstance(key, ast.Constant)
                or type(key.value) is not str
                or key.value in module_exports[module]
            )
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "__dict__"
        and audit._resolved_ast_name(node.value, aliases) in module_exports
    )


def _conditional_module_dict(node, aliases, audit, module_exports):
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return audit._resolved_ast_name(node.value, aliases) in module_exports
    return (
        isinstance(node, ast.Call)
        and audit._resolved_ast_name(node.func, aliases) == "vars"
        and bool(node.args)
        and audit._resolved_ast_name(node.args[0], aliases) in module_exports
    )


def _conditional_module_dict_path(node, aliases, audit):
    if isinstance(node, ast.Attribute):
        return audit._resolved_ast_name(node.value, aliases)
    if isinstance(node, ast.Call) and node.args:
        return audit._resolved_ast_name(node.args[0], aliases)
    return ""


def _conditional_module_dict_update(call, aliases, module_exports, audit):
    function = call.func
    if not isinstance(function, ast.Attribute) or function.attr != "update":
        return False
    if not _conditional_module_dict(function.value, aliases, audit, module_exports):
        return False
    if not call.args or not isinstance(call.args[0], ast.Dict):
        return True
    module = _conditional_module_dict_path(function.value, aliases, audit)
    exports = module_exports[module]
    keys = call.args[0].keys
    return any(
        key is None
        or not isinstance(key, ast.Constant)
        or type(key.value) is not str
        or key.value in exports
        for key in keys
    )


def _conditional_registry_path(node, audit, aliases):
    if isinstance(node, ast.Subscript):
        return _conditional_registry_path(node.value, audit, aliases)
    name = audit._resolved_ast_name(node, aliases)
    return name.startswith(
        (
            "copyreg.dispatch_table",
            "pickle.dispatch_table",
            "pickle.Pickler.dispatch_table",
        )
    )


def _conditional_module_name(path):
    from pathlib import PurePosixPath

    parts = PurePosixPath(path).with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _conditional_selected_path(node, aliases, audit, selected_classes):
    return (
        isinstance(node, (ast.Name, ast.Attribute))
        and audit._resolved_ast_name(node, aliases) in selected_classes
    )


def _prior_pickle_dump(scope, bytes_name, load_index, loaded_name, aliases, audit):
    """Find one earlier direct dump assignment with a same-library loader."""
    candidates = [
        (index, statement, _simple_scope_assignment(statement, bytes_name))
        for index, statement in enumerate(scope.body[:load_index])
        if _simple_scope_assignment(statement, bytes_name) is not None
    ]
    if len(candidates) != 1:
        return None
    index, statement, call = candidates[0]
    if (
        not isinstance(call, ast.Call)
        or _plain_scope_statement_index(call, scope) != index
        or len(call.args) != 1
        or not isinstance(call.args[0], ast.Name)
        or not _pickle_protocol_options_closed(call, scope, index, aliases, audit)
        or audit._normalized_call_name(call, aliases)
        != loaded_name.removesuffix("loads") + "dumps"
        or any(isinstance(argument, ast.Starred) for argument in call.args)
        or any(keyword.arg is None for keyword in call.keywords)
    ):
        return None
    return index, statement, call, call.args[0].id


def _pickle_protocol_integer(value):
    if sum(1 for _ in ast.walk(value)) > 3:
        return False
    try:
        return type(ast.literal_eval(value)) is int
    except (ValueError, TypeError, SyntaxError):
        return False


def _pickle_protocol_options_closed(call, scope, index, aliases, audit):
    if not call.keywords:
        return True
    if len(call.keywords) != 1 or call.keywords[0].arg != "protocol":
        return False
    value = call.keywords[0].value
    if _pickle_protocol_integer(value):
        return True
    if not isinstance(value, ast.Name):
        return False
    name = value.id
    if any(
        isinstance(item, (ast.Global, ast.Nonlocal)) and name in item.names
        for item in ast.walk(scope)
    ):
        return False
    if any(_pickle_nested_effect(statement, name, audit) for statement in scope.body):
        return False
    bindings = [
        (i, statement)
        for i, statement in enumerate(scope.body)
        if name in audit._bound_names(statement)
    ]
    stores = [
        item
        for item in ast.walk(scope)
        if isinstance(item, ast.Name)
        and item.id == name
        and isinstance(item.ctx, (ast.Store, ast.Del))
    ]
    if name not in audit._scope_parameters(scope):
        if len(bindings) != 1 or len(stores) != 1:
            return False
        position, statement = bindings[0]
        assigned = _simple_scope_assignment(statement, name)
        return (
            position < index
            and assigned is not None
            and _pickle_protocol_integer(assigned)
        )
    if bindings or stores or len(scope.decorator_list) != 1:
        return False
    return _pickle_protocol_parameter(scope, name, audit)


def _pickle_protocol_parameter(scope, name, audit):
    from .intent_quality import sanitizer_provider_unchanged

    module = getattr(scope, "_oracle_module", None)
    decorator = scope.decorator_list[0]
    if not isinstance(module, ast.Module) or not isinstance(decorator, ast.Call):
        return False
    if not _pickle_protocol_test_unreferenced(scope, module):
        return False
    aliases = audit._module_security_aliases(module)
    if (
        len(decorator.args) != 2
        or decorator.keywords
        or not isinstance(decorator.args[0], ast.Constant)
        or decorator.args[0].value != name
        or not isinstance(decorator.args[1], (ast.List, ast.Tuple))
    ):
        return False
    values = decorator.args[1].elts
    return (
        1 <= len(values) <= 64
        and all(_pickle_protocol_integer(value) for value in values)
        and sanitizer_provider_unchanged(
            decorator, aliases, "pytest.mark.parametrize", lambda _scope: module
        )
    )


def _pickle_protocol_test_unreferenced(scope, module):
    """A pytest domain cannot constrain a function reused by ordinary callers."""
    if scope not in module.body:
        return False
    definitions = [
        item for item in module.body if getattr(item, "name", None) == scope.name
    ]
    if definitions != [scope]:
        return False
    blocked = {
        scope.name,
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "eval",
        "exec",
        "__dict__",
        "__getattribute__",
    }
    return not any(
        isinstance(item, (ast.Name, ast.Attribute))
        and blocked.intersection(
            (getattr(item, "id", None), getattr(item, "attr", None))
        )
        for item in ast.walk(module)
    )


def _local_pickle_value(scope, name, dump_index, dump_argument, audit):
    """Require one unaliased local generation to reach the exact dump argument."""
    if name in audit._scope_parameters(scope):
        return False
    candidates = [
        (index, statement, _simple_scope_assignment(statement, name))
        for index, statement in enumerate(scope.body[:dump_index])
        if _simple_scope_assignment(statement, name) is not None
    ]
    if len(candidates) != 1:
        return False
    index, initializer, value = candidates[0]
    if index >= dump_index or not isinstance(
        value, (ast.Call, ast.Constant, ast.Dict, ast.List, ast.Tuple, ast.Set)
    ):
        return False
    parameters = audit._scope_parameters(scope)
    if any(
        isinstance(item, ast.Name)
        and item.id in parameters
        and isinstance(item.ctx, ast.Load)
        for item in ast.walk(value)
    ):
        return False
    prefix = scope.body[: dump_index + 1]
    if any(
        isinstance(item, (ast.Global, ast.Nonlocal)) and name in item.names
        for statement in scope.body
        for item in audit._body_nodes(statement)
    ):
        return False
    for statement in prefix:
        if _pickle_nested_effect(statement, name, audit):
            return False
        if statement is not initializer and name in audit._bound_names(statement):
            return False
    observations = [
        statement.value.value
        for statement in prefix
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id == "_"
        and isinstance(statement.value, ast.Attribute)
        and isinstance(statement.value.value, ast.Name)
        and statement.value.value.id == name
        and isinstance(statement.value.value.ctx, ast.Load)
    ]
    nodes = [item for statement in prefix for item in audit._body_nodes(statement)]
    stores = [
        item
        for item in nodes
        if isinstance(item, ast.Name)
        and item.id == name
        and isinstance(item.ctx, (ast.Store, ast.Del))
    ]
    target = (
        initializer.targets[0]
        if isinstance(initializer, ast.Assign)
        else initializer.target
    )
    occurrences = [
        item for item in nodes if isinstance(item, ast.Name) and item.id == name
    ]
    return (
        len(stores) == 1
        and stores[0] is target
        and isinstance(dump_argument, ast.Name)
        and dump_argument.id == name
        and isinstance(dump_argument.ctx, ast.Load)
        and len(occurrences) == 2 + len(observations)
        and {id(item) for item in occurrences}
        == {id(target), id(dump_argument), *(id(item) for item in observations)}
    )


def _pickle_nested_effect(statement, name, audit):
    """Reject captured values and evaluated headers without counting nested writes."""
    if isinstance(statement, ast.ClassDef):
        return _pickle_mentions((statement,), name)
    if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return any(
            isinstance(item, ast.Lambda)
            and (
                _pickle_mentions(
                    (
                        expression
                        for expression in (
                            *item.args.defaults,
                            *item.args.kw_defaults,
                        )
                        if expression is not None
                    ),
                    name,
                )
                or name not in _pickle_lambda_parameters(item)
                and _pickle_mentions((item.body,), name)
            )
            for item in ast.walk(statement)
        )
    headers = [
        *statement.decorator_list,
        *statement.args.defaults,
        *(item for item in statement.args.kw_defaults if item is not None),
        *(
            argument.annotation
            for argument in (
                *statement.args.posonlyargs,
                *statement.args.args,
                *statement.args.kwonlyargs,
            )
            if argument.annotation is not None
        ),
    ]
    if statement.args.vararg and statement.args.vararg.annotation:
        headers.append(statement.args.vararg.annotation)
    if statement.args.kwarg and statement.args.kwarg.annotation:
        headers.append(statement.args.kwarg.annotation)
    if statement.returns:
        headers.append(statement.returns)
    headers.extend(getattr(statement, "type_params", ()))
    if _pickle_mentions(headers, name):
        return True
    local_names = set(audit._scope_parameters(statement))
    for body_statement in statement.body:
        local_names.update(audit._bound_names(body_statement))
    if any(
        isinstance(item, ast.Nonlocal) and name in item.names
        for body_statement in statement.body
        for item in audit._body_nodes(body_statement)
    ):
        return True
    return name not in local_names and _pickle_mentions(statement.body, name)


def _pickle_lambda_parameters(node):
    arguments = node.args
    return {
        item.arg
        for item in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            *([arguments.vararg] if arguments.vararg else []),
            *([arguments.kwarg] if arguments.kwarg else []),
        )
    }


def _pickle_mentions(nodes, name):
    """Check a small list of lexical expressions for one exact binding."""
    return any(
        isinstance(item, ast.Name) and item.id == name
        for node in nodes
        for item in ast.walk(node)
    )


def _pickle_call_imported(module, scope, call, call_index, aliases, audit):
    """Require the exact serializer import to precede the call without rebinding."""
    raw_name = audit._call_name(call)
    head = raw_name.split(".", 1)[0]
    resolved = aliases.get(head)
    if not raw_name or not isinstance(resolved, str):
        return False
    module_aliases = audit._module_security_aliases(module)
    local_bindings = [
        (index, statement)
        for index, statement in enumerate(scope.body)
        if head in audit._bound_names(statement)
    ]
    if not local_bindings:
        return module_aliases.get(head) == resolved
    if len(local_bindings) != 1:
        return False
    index, statement = local_bindings[0]
    if index >= call_index or not isinstance(statement, (ast.Import, ast.ImportFrom)):
        return False
    return audit._security_aliases([statement]).get(head) == resolved


def _single_local_pickle_bytes_flow(scope, name, dump_statement, load_call):
    """Reuse exact source-origin occurrence matching for local serializer bytes."""
    from .context_efficiency import _capability_uses_match
    from .credential_role_constructor_provider import binding_occurrences

    target = (
        dump_statement.targets[0]
        if isinstance(dump_statement, ast.Assign)
        else dump_statement.target
    )
    uses = [target, load_call.args[0]]
    return (
        isinstance(target.ctx, ast.Store)
        and isinstance(uses[1].ctx, ast.Load)
        and binding_occurrences(scope.body, name) == [target]
        and _capability_uses_match(list(ast.walk(scope)), name, uses)
    )


def tenant_scope_read(audit, call: str, bindings: dict) -> dict:
    """Build a tenant-read contract row and raise ReviewAuditError when a call has multiple bindings."""
    values = bindings.get(call, ())
    if not isinstance(values, (tuple, list)) or len(values) > 1:
        raise audit.ReviewAuditError("Each scoped call requires at most one binding.")
    return {"call": call, "binding": values[0]} if values else {"call": call}


def validate_tenant_scopes(audit, workspace: Path, scopes: dict | None) -> dict:
    """Revalidate programmatic declarations through the same contract boundary."""
    if scopes is None:
        return {}
    if not isinstance(scopes, dict) or len(scopes) > audit.MAX_PATHS:
        raise audit.ReviewAuditError("Invalid tenant read scope map.")
    rows = [_tenant_scope_row(audit, path, scope) for path, scope in scopes.items()]
    return audit._tenant_scoped_entries(workspace, rows) if rows else {}


def _tenant_scope_row(audit, path, scope):
    if not isinstance(scope, dict) or set(scope) != {"calls", "bindings"}:
        raise audit.ReviewAuditError("Invalid scoped tenant calls and bindings.")
    if not isinstance(scope["calls"], (tuple, list)):
        raise audit.ReviewAuditError("Scoped calls must be a bounded sequence.")
    calls = audit._tenant_contract_calls(tuple(scope["calls"]))
    bindings = scope["bindings"]
    if not isinstance(bindings, dict) or set(bindings) - set(calls):
        raise audit.ReviewAuditError("Scoped bindings must name declared calls.")
    reads = [audit._tenant_scope_read(call, bindings) for call in calls]
    return {"path": path, "reads": reads}


def load_tenant_read_contract(
    audit, root: Path, path: str = ".factory/tenant-read-contract.json"
):
    """Load a bounded tenant-read declaration through the audit module's seams."""
    workspace = audit.Path(root).resolve()
    relative = audit._relative_path(path).as_posix()
    contract_path = (workspace / relative).resolve()
    if not contract_path.is_relative_to(workspace):
        raise audit.ReviewAuditError(
            "Tenant-read contract must remain inside the workspace."
        )
    if not contract_path.exists():
        return (), (), {"path": relative, "state": "missing", "policy_applies": False}
    try:
        data, evidence = audit._read(workspace, relative)
        contract = audit.json.loads(data, object_pairs_hook=audit._unique_fields)
    except (OSError, UnicodeError, audit.json.JSONDecodeError, ValueError) as exc:
        raise audit.ReviewAuditError(f"Invalid tenant-read contract: {exc}") from exc
    if not isinstance(contract, dict) or set(contract) != {"schema", "reads"}:
        raise audit.ReviewAuditError("Invalid tenant-read contract schema or fields.")
    if contract.get("schema") == "factory.tenant-read-contract.v2":
        evidence["scoped_reads"] = audit._tenant_scoped_entries(
            workspace, contract["reads"]
        )
        evidence["policy_applies"] = False
        evidence["state"] = "loaded"
        return (), (), evidence
    if contract.get("schema") != audit.TENANT_CONTRACT_SCHEMA:
        raise audit.ReviewAuditError("Invalid tenant-read contract schema or fields.")
    calls, bindings = audit._tenant_contract_entries(contract["reads"])
    normalized_calls = audit._tenant_contract_calls(calls)
    normalized_bindings = audit._tenant_contract_bindings(bindings, normalized_calls)
    flattened = tuple(
        f"{call}={binding}"
        for call, values in normalized_bindings.items()
        for binding in values
    )
    evidence["policy_applies"] = True
    evidence["state"] = "loaded"
    return normalized_calls, flattened, evidence


def tenant_contract_helpers(audit):
    """Return the tenant-contract loader, source reader, path checks, and binding validators used by audit reports."""
    return (
        load_tenant_read_contract,
        audit.Path,
        audit.ReviewAuditError,
        audit.json.loads,
        audit._relative_path,
        audit._read,
        audit._unique_fields,
        audit._tenant_scoped_entries,
        audit._tenant_scope_source,
        audit._tenant_contract_entries,
        audit._tenant_contract_calls,
        audit._tenant_contract_bindings,
    )


def _oracle_source_bindings(audit, row, sources):
    for path, digest in (
        (row["path"], row["test_sha256"]),
        (row["mutation"]["source_path"], row["mutation"]["source_sha256"]),
    ):
        if sources.get(path) != digest:
            raise audit.ReviewAuditError(
                "Runtime oracle source binding does not match this scan."
            )


def _oracle_test_identity(audit, raw, row):
    tree = ast.parse(raw, filename=row["path"])
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, audit._FUNCTION_NODES)
        and node.name == row["symbol"]
        and node.lineno == row["line"]
    ]
    if len(matches) != 1:
        raise audit.ReviewAuditError(
            "Runtime oracle test identity does not match this scan."
        )
    parents = audit._oracle_ancestor_map(tree.body).get(id(matches[0]), ())
    classes = [
        parent.name for parent, _child in parents if isinstance(parent, ast.ClassDef)
    ]
    if any(isinstance(parent, audit._FUNCTION_NODES) for parent, _child in parents):
        raise audit.ReviewAuditError(
            "Runtime oracle cannot credit a nested helper as a collected test."
        )
    return "::".join([row["path"], *classes, row["symbol"]])


def _oracle_case_ids_match(prefix, row):
    return not any(
        case != prefix and not case.startswith(prefix + "[")
        for case in row["baseline"]["case_ids"]
    )


def oracle_bound_row(audit, workspace: Path, row: dict, sources: dict) -> None:
    """Require both original test and mutated production source in this scan."""
    _oracle_source_bindings(audit, row, sources)
    raw = audit._security_source_bytes(workspace, row["path"])
    if (
        len(raw) > audit.MAX_BYTES
        or audit.sha256(raw).hexdigest() != row["test_sha256"]
    ):
        raise audit.ReviewAuditError(
            "Runtime oracle test source changed during reconciliation."
        )
    prefix = _oracle_test_identity(audit, raw, row)
    if not _oracle_case_ids_match(prefix, row):
        raise audit.ReviewAuditError(
            "Runtime oracle collected node does not match the qualified test."
        )


def reconcile_runtime_oracles(
    audit, workspace: Path, core: dict, evidence: tuple
) -> dict:
    """Credit only signed same-test mutation observations, keeping static history."""
    from .runtime_attestation import RuntimeAttestationError, verify_signed_test_oracles

    receipt, trust_root, trust_sha256, environment_sha256 = evidence
    if not all(value is not None for value in evidence):
        raise audit.ReviewAuditError(
            "Runtime oracle evidence requires receipt, trust root and both pins."
        )
    if not core["audit_coverage"]["complete"]:
        raise audit.ReviewAuditError(
            "Runtime oracle reconciliation requires a complete source scan."
        )
    try:
        verified = verify_signed_test_oracles(
            audit.local_file(workspace, receipt),
            audit.local_file(workspace, trust_root),
            trust_root_sha256=trust_sha256,
            source_manifest_sha256=core["source_manifest_sha256"],
            environment_sha256=environment_sha256,
        )
        sources = {item["path"]: item["sha256"] for item in core["sources"]}
        schema = verified.get("schema", "")
        manifests = {}
        for row in verified["tests"]:
            audit._oracle_bound_row(workspace, row, sources)
            manifests[id(row)] = audit.runtime_config_sources(
                workspace, core, row, schema
            )
        configuration_sources = core["oracle_context"]["configuration_sources"]
        covered_test_keys = {
            (finding["path"], finding["line"], finding["facts"].get("symbol"))
            for finding in core["findings"]
            if finding["code"] in {"QUALITY_UNKNOWN_TEST_ORACLE", "QUALITY_HOLLOW_TEST"}
            and (
                finding["code"] != "QUALITY_UNKNOWN_TEST_ORACLE"
                or schema == "factory.test-oracle-verification.v3"
            )
        }
        coverage_checked_test_paths = {
            row["path"]
            for row in verified["tests"]
            if (row["path"], row["line"], row["symbol"]) in covered_test_keys
        }
        mutation_paths = {row["mutation"]["source_path"] for row in verified["tests"]}
        config_paths = {
            item["path"]
            for items in [configuration_sources, *manifests.values()]
            for item in items
        }
        redundant_test_paths = (
            coverage_checked_test_paths - mutation_paths - config_paths
        )
        bindings = [
            item for item in core["sources"] if item["path"] not in redundant_test_paths
        ] + configuration_sources
        audit._verify_security_bindings(workspace, bindings)
    except (RuntimeAttestationError, RuntimeAuditError, OSError, ValueError) as error:
        raise audit.ReviewAuditError(
            "Runtime oracle evidence rejected: " + type(error).__name__
        ) from error
    rows = {(row["path"], row["line"], row["symbol"]): row for row in verified["tests"]}
    retained, reconciled = [], []

    for finding in core["findings"]:
        key = (finding["path"], finding["line"], finding["facts"].get("symbol"))
        row = rows.get(key)
        arguments = (workspace, finding, row, verified.get("schema", ""))
        config_manifest = manifests.get(id(row), []) if row is not None else []
        if audit.integrity.runtime_finding_coverage(*arguments, config_manifest):
            reconciled.append({"static_finding": finding, "runtime_evidence": row})
        else:
            retained.append(finding)
    core["findings"] = retained
    core["finding_counts"] = {
        code: sum(item["code"] == code for item in retained)
        for code in sorted({item["code"] for item in retained})
    }
    core["runtime_oracles"] = {
        **{key: value for key, value in verified.items() if key != "tests"},
        "reconciled": reconciled,
        "reconciled_count": len(reconciled),
        "unmatched_evidence_count": len(rows) - len(reconciled),
        "environment_sha256": environment_sha256,
    }
    core["state"] = audit._security_scan_state(
        core["sources"], retained, coverage=core.get("audit_coverage")
    )
    core["action_summary"] = audit._security_scan_action_summary(core["state"])
    return audit._seal_security_scan(core)


def _full_repository_workspace_context_state(
    engine, generation, audit, files, selected
):
    root = generation["root"]
    context_error = None
    context = {}
    try:
        context = engine._full_repository_security_context(generation, audit)
        generation["security_config_identity"] = context["config_identity"]
    except RuntimeAuditError as exc:
        if exc.code == "SOURCE_DRIFT":
            raise
        context_error = exc.code
    except (OSError, ValueError, TypeError, audit.ReviewAuditError) as exc:
        context_error = type(exc).__name__
    source_bytes = context.get("source_bytes", {})
    snapshots = context.get("snapshots", {})
    snapshot_state = {"paths": set(snapshots)}
    trees = {path: snapshots[path] for path in selected if path in snapshots}
    contexts = context.get("contexts", {})
    context_bindings = context.get("bindings", [])
    oracle_edges = []
    source_names = {path.relative_to(root).as_posix() for path in files}
    retained_names = {
        path.relative_to(root).as_posix(): engine.sha256_bytes(data)
        for path, data in source_bytes.items()
        if isinstance(path, Path) and isinstance(data, bytes)
    }
    byte_capture_complete = (
        context_error is None and set(retained_names) == source_names
    )
    source_capture_complete = byte_capture_complete and snapshot_state.get(
        "paths"
    ) == set(files)
    source_profile = {
        "capture_complete": source_capture_complete,
        "files_discovered": len(files),
        "files_bound": len(retained_names),
        "retention_limit_bytes": generation["source_retention_limit_bytes"],
        "source_manifest_sha256": engine.digest(sorted(retained_names.items())),
        "parseable_files": len(snapshot_state.get("paths", ())),
        "collection_state": generation["frame"].get("selected", {}).get("state"),
        "context_error": context_error,
    }
    context_generation = engine.digest(
        {
            "profile_schema": engine.FULL_REPOSITORY_CONTEXT_SCHEMA,
            "finding_tier_policy_sha256": _full_repository_workspace_tier_policy_sha256(),
            "inventory_sha256": generation["inventory_hash"],
            "configuration_sha256": generation["configuration"],
            "source_manifest_sha256": source_profile["source_manifest_sha256"],
            "bindings": context_bindings,
            "edges": oracle_edges,
            "security_config_identity": generation.get("security_config_identity", []),
        }
    )
    if generation.get("saved_context_generation_sha256") not in (
        None,
        context_generation,
    ):
        raise RuntimeAuditError(
            "SOURCE_DRIFT", "workspace context changed since the saved raw checkpoint"
        )
    return {
        "context": context,
        "context_error": context_error,
        "contexts": contexts,
        "context_bindings": context_bindings,
        "source_bytes": source_bytes,
        "snapshots": snapshots,
        "trees": trees,
        "snapshot_state": snapshot_state,
        "oracle_edges": oracle_edges,
        "source_names": source_names,
        "retained_names": retained_names,
        "byte_capture_complete": byte_capture_complete,
        "source_capture_complete": source_capture_complete,
        "source_profile": source_profile,
        "context_generation": context_generation,
    }


def _full_repository_workspace_reset_after_consume_error(
    engine, generation, state, error
):
    state["context_error"] = type(error).__name__
    state["source_bytes"] = {}
    state["contexts"] = {}
    state["context_bindings"] = []
    state["oracle_edges"] = []
    state["retained_names"] = {}
    state["byte_capture_complete"] = False
    state["source_capture_complete"] = False
    profile = state["source_profile"]
    profile.update(
        {
            "capture_complete": False,
            "files_bound": 0,
            "source_manifest_sha256": engine.digest([]),
            "context_error": state["context_error"],
        }
    )
    context_generation = engine.digest(
        {
            "profile_schema": engine.FULL_REPOSITORY_CONTEXT_SCHEMA,
            "finding_tier_policy_sha256": _full_repository_workspace_tier_policy_sha256(),
            "inventory_sha256": generation["inventory_hash"],
            "configuration_sha256": generation["configuration"],
            "source_manifest_sha256": profile["source_manifest_sha256"],
            "bindings": state["context_bindings"],
            "edges": state["oracle_edges"],
            "security_config_identity": generation.get("security_config_identity", []),
        }
    )
    if generation.get("saved_context_generation_sha256") not in (
        None,
        context_generation,
    ):
        raise RuntimeAuditError(
            "SOURCE_DRIFT", "workspace context changed since the saved raw checkpoint"
        )
    state["context_generation"] = context_generation


def _full_repository_workspace_consume_prefix(
    engine,
    generation,
    audit,
    results,
    files,
    selected,
    start,
    stop,
    source_by_name,
    deadline_monotonic,
    state,
    rows,
    consume_counts,
):
    root = generation["root"]
    cached_prefix = None
    if start and state["byte_capture_complete"]:
        cached_prefix = _full_repository_workspace_load_prefix(
            engine,
            generation,
            results,
            files[:start],
            source_by_name,
            state["context_generation"],
        )
    if cached_prefix is not None:
        for item in cached_prefix:
            rows[root / item["path"]] = (
                item["binding"],
                item["findings"],
                item["status"],
            )
        scan_selected = files[start:stop]
    else:
        scan_selected = selected
    generation["workspace_prefix_cache_rows_reused"] = cached_prefix is not None
    if state["context_error"] is None:
        try:
            _full_repository_workspace_consume(
                engine,
                generation,
                audit,
                root,
                scan_selected,
                rows,
                state["trees"],
                state["snapshot_state"],
                consume_counts,
                deadline_monotonic,
                state["snapshots"],
                state["context"]["fingerprints"],
                state["contexts"],
                state["source_bytes"],
            )
        except (
            OSError,
            ValueError,
            TypeError,
            audit.ReviewAuditError,
            RuntimeAuditError,
        ) as error:
            rows.clear()
            state["trees"].clear()
            cached_prefix = None
            generation["workspace_prefix_cache_rows_reused"] = False
            _full_repository_workspace_reset_after_consume_error(
                engine, generation, state, error
            )
    return cached_prefix


def _full_repository_workspace_batch_capture(
    engine, generation, audit, results, deadline_monotonic
):
    root, files = generation["root"], generation["files"]
    start = len(results)
    stop = min(len(files), start + engine.FULL_REPOSITORY_BATCH_LIMIT)
    selected = files[:stop]
    rows = {}
    consume_counts = {"calls": 0, "attempted_rows": 0, "completed_rows": 0}
    state = _full_repository_workspace_context_state(
        engine, generation, audit, files, selected
    )
    generation["context_generation_sha256"] = state["context_generation"]
    source_by_name = {row["path"]: row for row in generation["inventory"]}
    cached_prefix = _full_repository_workspace_consume_prefix(
        engine,
        generation,
        audit,
        results,
        files,
        selected,
        start,
        stop,
        source_by_name,
        deadline_monotonic,
        state,
        rows,
        consume_counts,
    )
    generation["context_generation_sha256"] = state["context_generation"]
    context_error = state["context_error"]
    context_bindings = state["context_bindings"]
    source_bytes = state["source_bytes"]
    trees = state["trees"]
    oracle_edges = state["oracle_edges"]
    source_names = state["source_names"]
    source_capture_complete = state["source_capture_complete"]
    byte_capture_complete = state["byte_capture_complete"]
    source_profile = state["source_profile"]
    generation["workspace_evidence"] = {
        "sources": source_profile,
        "oracle_context": {
            "state": "captured"
            if source_capture_complete and not generation["collection_incomplete"]
            else "INCOMPLETE",
            "binding_count": len(context_bindings),
            "edge_count": len(oracle_edges),
            "source_retention_limit_bytes": generation[
                "source_retention_limit_bytes"
            ],
            "global_consumer_closure_verified": False,
        },
        "primitive_observations": [],
        "findings": [],
        "audit_coverage": {"complete": False, "files_processed": 0},
    }
    return {
        "root": root,
        "files": files,
        "start": start,
        "stop": stop,
        "selected": selected,
        "rows": rows,
        "consume_counts": consume_counts,
        "cached_prefix": cached_prefix,
        "source_by_name": source_by_name,
        "context_error": context_error,
        "context_bindings": context_bindings,
        "source_bytes": source_bytes,
        "trees": trees,
        "oracle_edges": oracle_edges,
        "source_names": source_names,
        "source_capture_complete": source_capture_complete,
        "byte_capture_complete": byte_capture_complete,
    }


def _full_repository_workspace_batch_assessment(
    engine,
    generation,
    audit,
    root,
    files,
    selected,
    source_by_name,
    rows,
    trees,
    source_bytes,
    results,
    deadline_monotonic,
    start,
    cached_prefix,
    stop,
    byte_capture_complete,
    source_capture_complete,
    context_bindings,
    oracle_edges,
    context_error,
    source_names,
):
    captured, bindings, context_findings = _full_repository_workspace_primary_rows(
        engine,
        generation,
        audit,
        root,
        files,
        selected,
        source_by_name,
        rows,
        trees,
        source_bytes,
        results,
        deadline_monotonic,
    )
    batch = captured[start:]
    generation["workspace_checkpoint_rows_recomputed_and_matched"] = (
        0 if cached_prefix is not None else start
    )
    _full_repository_workspace_cache_raw_rows(
        generation,
        root,
        selected,
        captured,
        rows,
        byte_capture_complete,
        stop,
    )
    (
        observations,
        active_findings,
        partition_state,
        partition_error,
        all_primaries_assessed,
    ) = _full_repository_workspace_partition(
        engine,
        generation,
        audit,
        root,
        files,
        stop,
        captured,
        bindings,
        context_findings,
        source_names,
        source_bytes,
        source_capture_complete,
        context_bindings,
        oracle_edges,
        context_error,
    )
    tier_source_bytes = {
        path.relative_to(root).as_posix(): data
        for path, data in source_bytes.items()
        if isinstance(path, Path)
        and isinstance(data, bytes)
        and path.is_relative_to(root)
    }
    with audit._security_only_scan_context(
        generation["context_profile"] == "workspace-v2"
    ):
        finding_tiers = _full_repository_workspace_finding_tiers(
            context_findings,
            observations if partition_state == "VALIDATED" else [],
            bindings,
            tier_source_bytes,
            coverage_state=(source_capture_complete and all_primaries_assessed),
            partition_state=partition_state,
        )
    return {
        "batch": batch,
        "captured": captured,
        "context_findings": context_findings,
        "observations": observations,
        "active_findings": active_findings,
        "partition_state": partition_state,
        "partition_error": partition_error,
        "all_primaries_assessed": all_primaries_assessed,
        "finding_tiers": finding_tiers,
    }


def _full_repository_workspace_record_batch_evidence(
    engine,
    generation,
    start,
    stop,
    cached_prefix,
    files,
    batch,
    captured,
    consume_counts,
    source_capture_complete,
    all_primaries_assessed,
    finding_tiers,
    observations,
    partition_state,
    partition_error,
    context_findings,
    active_findings,
):
    generation["workspace_evidence"].update(
        {
            "finding_tiers": finding_tiers,
            "primitive_observations": observations,
            "primitive_partition": {
                "state": partition_state,
                "error_code": partition_error,
            },
            "primary_processing": {
                "checkpoint_rows_requested": start,
                "checkpoint_rows_reused_verified": start
                if cached_prefix is not None
                else 0,
                "checkpoint_rows_recomputed_and_matched": 0
                if cached_prefix is not None
                else start,
                "new_primary_rows_requested": stop - start,
                "new_primary_rows_assessed": len(batch),
                "total_prefix_rows_assessed": len(captured),
                "consume_call_limit": engine.FULL_REPOSITORY_BATCH_LIMIT,
                "consume_calls": consume_counts["calls"],
                "consume_rows_attempted": consume_counts["attempted_rows"],
                "consume_rows_completed": consume_counts["completed_rows"],
            },
            "findings_authority": "native_source_bound_partition"
            if partition_state == "VALIDATED"
            else "raw_unverified_source_analysis",
            "raw_findings": context_findings,
            "findings": sorted(
                active_findings,
                key=lambda item: (item["path"], item.get("line", 0), item["code"]),
            ),
            "audit_coverage": {
                "complete": source_capture_complete and all_primaries_assessed,
                "files_processed": stop,
                "files_discovered": len(files),
            },
        }
    )


def full_repository_workspace_scan_batch(
    engine, generation, audit, results, deadline_monotonic
):
    """Rebuild one full source context, then consume only the bounded primary prefix."""

    engine._full_repository_check_soft_deadline(deadline_monotonic)
    capture = _full_repository_workspace_batch_capture(
        engine, generation, audit, results, deadline_monotonic
    )
    root = capture["root"]
    files = capture["files"]
    start = capture["start"]
    stop = capture["stop"]
    selected = capture["selected"]
    rows = capture["rows"]
    consume_counts = capture["consume_counts"]
    cached_prefix = capture["cached_prefix"]
    source_by_name = capture["source_by_name"]
    context_error = capture["context_error"]
    context_bindings = capture["context_bindings"]
    source_bytes = capture["source_bytes"]
    trees = capture["trees"]
    oracle_edges = capture["oracle_edges"]
    source_names = capture["source_names"]
    source_capture_complete = capture["source_capture_complete"]
    byte_capture_complete = capture["byte_capture_complete"]

    assessment = _full_repository_workspace_batch_assessment(
        engine,
        generation,
        audit,
        root,
        files,
        selected,
        source_by_name,
        rows,
        trees,
        source_bytes,
        results,
        deadline_monotonic,
        start,
        cached_prefix,
        stop,
        byte_capture_complete,
        source_capture_complete,
        context_bindings,
        oracle_edges,
        context_error,
        source_names,
    )
    batch = assessment["batch"]
    captured = assessment["captured"]
    context_findings = assessment["context_findings"]
    observations = assessment["observations"]
    active_findings = assessment["active_findings"]
    partition_state = assessment["partition_state"]
    partition_error = assessment["partition_error"]
    all_primaries_assessed = assessment["all_primaries_assessed"]
    finding_tiers = assessment["finding_tiers"]
    _full_repository_workspace_record_batch_evidence(
        engine,
        generation,
        start,
        stop,
        cached_prefix,
        files,
        batch,
        captured,
        consume_counts,
        source_capture_complete,
        all_primaries_assessed,
        finding_tiers,
        observations,
        partition_state,
        partition_error,
        context_findings,
        active_findings,
    )
    engine._full_repository_check_soft_deadline(deadline_monotonic)
    return batch


def _full_repository_workspace_cache_raw_rows(
    generation, root, selected, captured, rows, byte_capture_complete, stop
):
    if not byte_capture_complete or len(captured) != stop or len(rows) != stop:
        return
    generation["workspace_prefix_raw_rows"] = [
        {
            "path": path.relative_to(root).as_posix(),
            "binding": copy.deepcopy(rows[path][0]),
            "findings": copy.deepcopy(rows[path][1]),
            "status": rows[path][2],
        }
        for path in selected
        if path in rows
    ]


def _full_repository_workspace_tier_policy_sha256():
    """Expose the exact tier policy digest to context-generation identity."""
    from .primitive_observation_binding import finding_tier_policy_sha256

    return finding_tier_policy_sha256()


def _full_repository_workspace_finding_tiers(
    raw_findings,
    primitive_observations,
    sources,
    source_bytes,
    *,
    coverage_state,
    partition_state,
):
    """Use the same source-bound tier policy as the bounded security report."""
    from .primitive_observation_binding import build_finding_tier_report

    return build_finding_tier_report(
        raw_findings,
        primitive_observations,
        sources,
        source_bytes,
        coverage_state=coverage_state,
        partition_state=partition_state,
    )


def _full_repository_workspace_primary_rows(
    engine,
    generation,
    audit,
    root,
    files,
    selected,
    source_by_name,
    rows,
    trees,
    source_bytes,
    results,
    deadline_monotonic,
):
    """Rebuild the selected primary prefix and compare trusted checkpoint rows."""
    eligible = {item.resolve(): item for item in files if not item.is_symlink()}
    captured, bindings, context_findings = [], [], []
    for path in selected:
        engine._full_repository_check_soft_deadline(deadline_monotonic)
        scanned = rows.get(path)
        tree = trees.get(path)
        source = source_by_name[path.relative_to(root).as_posix()]
        if scanned is None:
            raw, findings, status, tree = engine._full_repository_native_scan(
                root, path, source, generation["patterns"], audit
            )
            rows[path] = (raw, findings, status)
            if tree is not None:
                trees[path] = tree
        else:
            raw, findings, status = scanned
            tree = _full_repository_workspace_dependency_tree(
                engine,
                audit,
                root,
                path,
                source,
                source_bytes.get(path),
                raw,
                status,
            )
        if raw is not None:
            bindings.append(raw)
        context_findings.extend(findings)
        captured.append(
            engine._full_repository_primary(
                root,
                path,
                source,
                generation["patterns"],
                audit,
                eligible,
                (raw, findings, status, tree),
            )
        )
    for index, previous in enumerate(results):
        if captured[index] != previous:
            raise RuntimeAuditError(
                "INVALID_CHECKPOINT",
                "saved raw row differs under current workspace context",
            )
    return captured, bindings, context_findings


def _full_repository_workspace_partition(
    engine,
    generation,
    audit,
    root,
    files,
    stop,
    captured,
    bindings,
    context_findings,
    source_names,
    source_bytes,
    source_capture_complete,
    context_bindings,
    oracle_edges,
    context_error,
):
    """Publish a whole partition transaction or retain rejected raw findings."""
    observations = []
    from .primitive_observation_binding import rejected_primitive_proof

    active_findings = [
        rejected_primitive_proof(finding)
        if (
            finding.get("facts", {}).get("disposition", "").startswith("PROVEN_")
            or finding.get("facts", {}).get("disposition")
            in {
                "ENDPOINT_DECLARATION_ROLE_PROVEN",
                "TEST_OWNED_LOCAL_FIXTURE",
                "TEST_OWNED_APPLICATION_CREDENTIAL",
                "SOURCE_PRESENTATION_METADATA",
            }
        )
        else finding
        for finding in context_findings
    ]
    partition_state = "INCOMPLETE"
    partition_error = (
        "E_SOURCE_RETENTION"
        if context_error == "E_SOURCE_RETENTION"
        else "SOURCE_CONTEXT_ERROR"
        if context_error
        else "COLLECTION_CONFIG_UNSUPPORTED"
        if generation["collection_incomplete"]
        else "SOURCE_CAPTURE_INCOMPLETE"
        if not source_capture_complete
        else "PRIMARY_INVENTORY_INCOMPLETE"
    )
    primary_paths = {row["path"] for row in bindings}
    all_primaries_assessed = (
        stop == len(files)
        and len(captured) == len(files)
        and len(bindings) == len(source_names)
        and primary_paths == source_names
        and all(row["status"] == "audited" for row in captured)
    )
    if (
        source_capture_complete
        and all_primaries_assessed
        and not generation["collection_incomplete"]
    ):
        try:
            current_configs = [
                engine._full_repository_configuration_binding(root, row["path"])
                for row in generation.get("security_config_identity", [])
            ]
            if current_configs != generation.get("security_config_identity", []):
                raise RuntimeAuditError(
                    "SOURCE_DRIFT", "security config generation changed"
                )
            database = None
            audit._verify_security_bindings(root, context_bindings + bindings)
            configuration_bindings = [
                row for row in context_bindings if row["path"] not in source_names
            ]
            partitioned_findings = []
            for offset in range(0, len(captured), engine.FULL_REPOSITORY_BATCH_LIMIT):
                group = captured[offset : offset + engine.FULL_REPOSITORY_BATCH_LIMIT]
                group_findings = [
                    finding for row in group for finding in row["findings"]
                ]
                group_outcomes = {
                    key: sum(row["status"] == key for row in group)
                    for key in ("syntax_error", "unreadable", "too_large", "audited")
                }
                group_paths = [root / row["path"] for row in group]
                primitive_bytes = audit._app_source_bytes(
                    root, group_findings, bindings, source_bytes
                )
                quality = audit._security_scan_report(
                    group_paths,
                    group_findings,
                    bindings,
                    dict(Counter(item["code"] for item in group_findings)),
                    group_outcomes,
                    (),
                    {},
                    oracle_edges,
                    configuration_bindings,
                    database,
                    False,
                    primitive_bytes,
                    security_only=generation["context_profile"] == "workspace-v2",
                )
                observations.extend(quality.get("primitive_observations", []))
                partitioned_findings.extend(quality["findings"])
            active_findings = partitioned_findings
            partition_state, partition_error = "VALIDATED", None
        except (
            OSError,
            ValueError,
            TypeError,
            audit.ReviewAuditError,
            RuntimeAuditError,
        ) as exc:
            observations = []
            partition_state, partition_error = "ERROR", type(exc).__name__
    return (
        observations,
        active_findings,
        partition_state,
        partition_error,
        all_primaries_assessed,
    )


def _full_repository_workspace_consume(
    engine,
    generation,
    audit,
    root,
    selected,
    rows,
    trees,
    snapshot_state,
    consume_counts,
    deadline_monotonic,
    snapshots,
    fingerprints,
    captured_contexts,
    retained,
):
    """Consume captured security trees synchronously in bounded chunks."""
    snapshot_state["paths"] = set(snapshots)
    trees.update({path: snapshots[path] for path in selected if path in snapshots})
    try:
        for offset in range(0, len(selected), engine.FULL_REPOSITORY_BATCH_LIMIT):
            engine._full_repository_check_soft_deadline(deadline_monotonic)
            group = selected[offset : offset + engine.FULL_REPOSITORY_BATCH_LIMIT]
            consume_counts["calls"] += 1
            consume_counts["attempted_rows"] += len(group)
            group_rows = {}
            for path in group:
                tree = snapshots.get(path)
                if tree is None:
                    continue
                context = {
                    **captured_contexts.get(path, {}),
                    "_security_source_context": (root, retained),
                }
                group_rows[path] = audit._security_scan_file_snapshot(
                    root,
                    path,
                    (),
                    {},
                    context,
                    generation["patterns"],
                    retained.get(path),
                    tree,
                    fingerprints.get(path),
                    security_only=generation["context_profile"] == "workspace-v2",
                )
            rows.update(group_rows)
            consume_counts["completed_rows"] += len(group_rows)
    finally:
        snapshots.clear()


def _full_repository_workspace_dependency_tree(
    engine, audit, root, path, source, data, binding, status
):
    """Derive lexical imports from the same bytes as the audited native row."""
    if status != "audited":
        return None
    if (
        not isinstance(data, bytes)
        or len(data) > audit.MAX_BYTES
        or not isinstance(binding, dict)
        or engine.sha256_bytes(data) != binding.get("sha256")
        or binding.get("sha256") != source["sha256"]
    ):
        raise RuntimeAuditError(
            "SOURCE_DRIFT", "dependency source differs from audited bytes"
        )
    try:
        return audit._measure_parse(audit.ast.parse, data, root, path)
    except (SyntaxError, UnicodeError, RecursionError) as exc:
        raise RuntimeAuditError(
            "SOURCE_DRIFT", "audited dependency source no longer parses"
        ) from exc


def _full_repository_workspace_security_context(engine, generation, audit):
    from .context_efficiency import bind_application_fixture_context
    from .import_context import CapturedImportInventory
    root, files = generation["root"], generation["files"]
    retention_limit = generation.get("source_retention_limit_bytes")
    capture_options = {} if retention_limit is None else {"retention_limit": retention_limit}
    captured, bindings, _manifest, _cacheable = audit._oracle_source_inputs(root, files, **capture_options)
    inventory = {row["path"]: row for row in generation.get("inventory", ())}
    for binding in bindings:
        prior = inventory.get(binding["path"])
        if prior is not None and prior.get("sha256") != binding.get("sha256"):
            raise RuntimeAuditError(
                "SOURCE_DRIFT", "source changed between inventory and context capture"
            )
    if len(captured) < len(bindings):
        raise RuntimeAuditError(
            "E_SOURCE_RETENTION", "workspace source retention budget exhausted"
        )
    snapshots = audit.contracts.bound_snapshots(root, files, captured, bindings)
    hashes = {root / row["path"]: row["sha256"] for row in bindings}
    contexts = {path: {} for path in snapshots}
    config_bindings = []
    config_bytes = {}
    names = {row["path"] for row in generation["frame"]["candidates"]}
    names.add("requirements.txt")
    config_identity = []
    for name in sorted(names):
        row = engine._full_repository_configuration_binding(root, name)
        config_identity.append(row)
        if row.get("state") != "read":
            if row.get("state") != "absent":
                raise RuntimeAuditError(
                    "E_CONTEXT_CONFIG", "security config unavailable"
                )
            continue
        raw = audit._security_source_bytes(root, name)
        if len(raw) > audit.MAX_BYTES or engine.sha256_bytes(raw) != row["sha256"]:
            raise RuntimeAuditError("SOURCE_DRIFT", "captured security config changed")
        config_bytes[name] = raw
        config_bindings.append(
            {"path": name, "sha256": row["sha256"], "bytes": len(raw)}
        )
    def captured_config(_root, name):
        if name not in config_bytes:
            raise FileNotFoundError(name)
        return config_bytes[name]
    symbolic_imports = {}
    source_paths = set(snapshots)
    binding_paths = [root / row["path"] for row in bindings]
    symbolic_inputs_complete = (
        callable(getattr(audit, "_oracle_imports", None))
        and source_paths == set(captured) == set(hashes)
        and len(binding_paths) == len(set(binding_paths)) == len(source_paths)
        and all(
            isinstance(hashes[path], str)
            and len(hashes[path]) == 64
            and hashes[path] == hashlib.sha256(captured[path]).hexdigest()
            for path in source_paths
        )
    )
    if symbolic_inputs_complete:
        eligible = CapturedImportInventory(root, tuple(snapshots))
        symbolic_imports = {
            path: audit._oracle_imports(root, path, tree, eligible, captured=True)
            for path, tree in snapshots.items()
        }
        symbolic_inputs_complete = set(symbolic_imports) == source_paths
    if symbolic_inputs_complete:
        from .provenance import bind_credential_consumers

        bind_credential_consumers(
            audit.integrity,
            root,
            snapshots,
            symbolic_imports,
            contexts,
            captured,
            inventory=hashes,
        )
    bind_application_fixture_context(
        root,
        snapshots,
        contexts,
        config_bindings,
        captured_config,
        audit.MAX_BYTES,
        source_bytes=captured,
        source_inventory=hashes,
        imports=symbolic_imports if symbolic_inputs_complete else None,
    )
    audit.integrity.bind_fixed_program_workspace(
        root, contexts, snapshots, files, captured
    )
    return {
        "contexts": contexts,
        "source_bytes": captured,
        "bindings": bindings + config_bindings,
        "snapshots": snapshots,
        "symbolic_imports": symbolic_imports if symbolic_inputs_complete else {},
        "fingerprints": {},
        "config_identity": config_identity,
    }


def _pickle_direct_dump_origin(node, scope, load_index, loaded_name, aliases, audit):
    dumps_name = loaded_name.removesuffix("loads") + "dumps"
    if isinstance(node.args[0], ast.Call):
        call = node.args[0]
        return (
            (load_index, scope.body[load_index], call, None)
            if audit._normalized_call_name(call, aliases) == dumps_name
            else None
        )
    name = node.args[0].id
    candidates = [
        (index, statement, _simple_scope_assignment(statement, name))
        for index, statement in enumerate(scope.body[:load_index])
        if isinstance(_pickle_statement_target(statement), ast.Name)
        and _pickle_statement_target(statement).id == name
    ]
    if len(candidates) != 1:
        return None
    index, statement, call = candidates[0]
    if (
        not isinstance(call, ast.Call)
        or audit._normalized_call_name(call, aliases) != dumps_name
    ):
        return None
    return (
        (index, statement, call, name)
        if _pickle_bytes_flow_closed(scope, name, statement, node)
        else None
    )
