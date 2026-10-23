"""Runtime evidence joins, callback reconciliation, and advisory repair routing."""

import ast
import copy
import hashlib
import re
from collections import Counter, defaultdict
from typing import Any
from pathlib import Path

from .runtime_audit_common import RuntimeAuditError
from .runtime_audit_contract import LANES
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
    _fixed_literal_value,
    finite_literal_eval_input_witness,  # noqa: F401
    finite_template_program_hashes,
)

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
        return {}
    normalized, literal, program_bytes, statement_kinds = context
    span = _fixed_program_literal_span(literal)
    if span is None:
        return {}
    return {
        "schema": "factory.fixed-literal-program.v1",
        "disposition": "PROVEN_FIXED_LITERAL_PROGRAM",
        "source_path": source_path,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "literal_span": span,
        "program_sha256": hashlib.sha256(program_bytes).hexdigest(),
        "statement_kinds": statement_kinds,
        "profile": {
            "call": f"builtins.{normalized}",
            "identity": "caller_proved_lexical_source_context",
            "namespace": "implicit_caller_namespace",
            "scope": scope_profile if isinstance(scope_profile, str) else None,
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
        "nodes_examined": 0,
        "source_hashes": {},
    }
    source_hashes = _workspace_source_hashes(snapshots, files)
    if source_hashes is None:
        return profile
    profile["source_hashes"] = source_hashes
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
        "nodes_examined": nodes_examined,
        "source_hashes": source_hashes,
    }


def workspace_builtin_helpers():
    """Return workspace builtin and source-analysis helpers used by fixed-program and literal-input proofs."""
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
        _local_pickle_roundtrip,
        _plain_scope_statement_index,
        _simple_scope_assignment,
        _prior_pickle_dump,
        _pickle_protocol_integer,
        _pickle_protocol_options_closed,
        _pickle_protocol_parameter,
        _pickle_protocol_test_unreferenced,
        _local_pickle_value,
        _pickle_nested_effect,
        _pickle_lambda_parameters,
        _pickle_mentions,
        _pickle_call_imported,
        _single_local_pickle_bytes_flow,
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
    )


def credential_validation_helpers():
    """Collect callable validators from the credential-related analysis modules while excluding imported callables."""
    from . import (
        credential_endpoint_admission,
        credential_role_constructor_provider as credential_role_scope_bindings,
    )
    from . import finite_capture, semantic_credential_sensor

    modules = (
        credential_role_scope_bindings,
        finite_capture,
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
    )


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
        if not self.complete:
            return {}
        result = {}
        for (path, cls, member), declaration in self.members.items():
            refs = self.refs.get(("class", path, cls), [])
            if not self._tick(len(refs)):
                return {}
            relevant = [
                (p, node, tail)
                for p, node, tail in refs
                if not tail or tail[0] == member
            ]
            if not any(tail == (member,) for _, _, tail in relevant):
                continue
            if not all(
                (not tail and self.public(p, node))
                or tail == (member,)
                and isinstance(node.ctx, ast.Load)
                and self.public(p, node)
                for p, node, tail in relevant
            ):
                continue
            result[path, declaration.lineno, member] = [
                {
                    "path": p.relative_to(self.root).as_posix(),
                    "line": node.lineno,
                    "source_sha256": getattr(
                        self.trees[p], "_oracle_source_sha256", None
                    ),
                    **(
                        {"source_profile": self.source_profiles[p]}
                        if p in self.source_profiles
                        else {}
                    ),
                }
                for p, node, tail in relevant
                if tail
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

    target = (
        dump_statement.targets[0]
        if isinstance(dump_statement, ast.Assign)
        else dump_statement.target
    )
    uses = [target, load_call.args[0]]
    return (
        isinstance(target.ctx, ast.Store)
        and isinstance(uses[1].ctx, ast.Load)
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
        bindings = core["sources"] + core["oracle_context"]["configuration_sources"]
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
    except (
        OSError,
        ValueError,
        TypeError,
        audit.ReviewAuditError,
        RuntimeAuditError,
    ) as exc:
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
        "source_manifest_sha256": engine.digest(sorted(retained_names.items())),
        "parseable_files": len(snapshot_state.get("paths", ())),
        "collection_state": generation["frame"].get("selected", {}).get("state"),
        "context_error": context_error,
    }
    context_generation = engine.digest(
        {
            "profile_schema": engine.FULL_REPOSITORY_CONTEXT_SCHEMA,
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


def full_repository_workspace_scan_batch(
    engine, generation, audit, results, deadline_monotonic
):
    """Rebuild one full source context, then consume only the bounded primary prefix."""

    engine._full_repository_check_soft_deadline(deadline_monotonic)
    root, files = generation["root"], generation["files"]
    start = len(results)
    stop = min(len(files), start + engine.FULL_REPOSITORY_BATCH_LIMIT)
    selected = files[:stop]
    rows = {}
    consume_counts = {"calls": 0, "attempted_rows": 0, "completed_rows": 0}
    state = _full_repository_workspace_context_state(
        engine, generation, audit, files, selected
    )
    context_generation = state["context_generation"]
    generation["context_generation_sha256"] = context_generation
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
            "global_consumer_closure_verified": False,
        },
        "primitive_observations": [],
        "findings": [],
        "audit_coverage": {"complete": False, "files_processed": 0},
    }

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
    generation["workspace_evidence"].update(
        {
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
        "SOURCE_CONTEXT_ERROR"
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
    """Capture a security-only generation without project test-oracle work."""
    from .context_efficiency import bind_application_fixture_context

    root, files = generation["root"], generation["files"]
    captured, bindings, _manifest, _cacheable = audit._oracle_source_inputs(root, files)
    snapshots = audit.contracts.bound_snapshots(root, files, captured, bindings)
    hashes = {root / row["path"]: row["sha256"] for row in bindings}
    contexts = {path: {} for path in snapshots}
    config_bindings = []
    config_bytes = {}
    # Bind selected, competing and absent security config separately from Python.
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

    # Existing fixture queries resolve their own captured providers. No new
    # imported symbolic/metadata role is admitted without its resolver contract.
    bind_application_fixture_context(
        root,
        snapshots,
        contexts,
        config_bindings,
        captured_config,
        audit.MAX_BYTES,
        source_bytes=captured,
        source_inventory=hashes,
    )
    return {
        "contexts": contexts,
        "source_bytes": captured,
        "bindings": bindings + config_bindings,
        "snapshots": snapshots,
        # Native consumers parse the current captured bytes afresh. Empty
        # fingerprints select that existing fail-closed path; no producer AST
        # can substitute its structure for the byte-bound native scan.
        "fingerprints": {},
        "config_identity": config_identity,
    }
