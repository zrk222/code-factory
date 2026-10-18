"""Runtime evidence joins, callback reconciliation, and advisory repair routing."""

import ast
import hashlib
import re
from collections import defaultdict
from typing import Any

from .runtime_audit_common import RuntimeAuditError
from .runtime_audit_contract import LANES


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


def closed_declaration_input_witness(node, call_name, *, source_bytes, source_path):
    """Recognize fixed Python 3.12 alias input without compiling or executing it."""
    if (
        not isinstance(source_bytes, bytes)
        or not isinstance(source_path, str)
        or not source_path
    ):
        return {}
    alias = _closed_declaration_program(node, call_name)
    if alias is None:
        return {}
    try:
        tree = ast.parse(source_bytes)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return {}

    def span(n):
        return [
            getattr(n, k, None)
            for k in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        ]

    matches = [
        n for n in ast.walk(tree) if isinstance(n, ast.Call) and span(n) == span(node)
    ]
    if len(matches) != 1 or ast.dump(matches[0]) != ast.dump(node):
        return {}
    call = matches[0]
    if not _closed_declaration_binding(tree, call) or not _closed_declaration_namespace(
        tree, call, alias
    ):
        return {}
    return {
        "schema": "factory.closed-declaration-input.v1",
        "disposition": "PROVEN_CLOSED_DECLARATION_INPUT",
        "source_path": source_path,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "call_span": span(call),
        "literal_span": span(call.args[0]),
        "program_sha256": hashlib.sha256(call.args[0].value.encode()).hexdigest(),
        "grammar_profile": "python3.12-type-alias-subset-v1",
        "hypothesis": "ARGUMENT_CODE_INJECTION",
        "input_effect": "CLOSED_INERT_DECLARATION",
        "runtime_assurance": "INCOMPLETE",
        "target_execution": "not_performed",
    }


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
        if any(
            not isinstance(
                n,
                (
                    ast.Expression,
                    ast.Name,
                    ast.Subscript,
                    ast.Tuple,
                    ast.List,
                    ast.Load,
                    ast.Constant,
                    ast.BinOp,
                    ast.BitOr,
                ),
            )
            for n in ast.walk(expression)
        ):
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


def finite_literal_eval_input_witness(node, call_name, *, source_bytes, source_path):
    """Prove finite source input only, not the effects of resolving type objects."""
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
        return {}
    try:
        tree = ast.parse(source_bytes)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return {}

    def span(n):
        return [
            getattr(n, k, None)
            for k in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        ]

    matches = [
        n for n in ast.walk(tree) if isinstance(n, ast.Call) and span(n) == span(node)
    ]
    if len(matches) != 1 or ast.dump(matches[0]) != ast.dump(node):
        return {}
    call = matches[0]
    comprehension = _finite_eval_comprehension(tree, call)
    domain = _finite_eval_domain(comprehension, call)
    if domain is None:
        return {}
    prefix = _finite_eval_module_prefix(tree, comprehension)
    if prefix is None or not _closed_declaration_binding(prefix, call):
        return {}
    domain_node, programs = domain
    import json

    return {
        "schema": "factory.finite-eval-input.v1",
        "disposition": "PROVEN_FINITE_LITERAL_EVAL_INPUT",
        "source_path": source_path,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "call_span": span(call),
        "domain_span": span(domain_node),
        "comprehension_span": span(comprehension),
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
    call = _fixed_literal_call(node, call_name)
    if (
        call is None
        or builtin_identity_proven is not True
        or not isinstance(source_bytes, bytes)
        or not isinstance(source_path, str)
        or not source_path
    ):
        return {}
    normalized, literal = call
    program = literal.value
    try:
        program_bytes = program.encode("utf-8")
    except UnicodeEncodeError:
        return {}
    if len(program_bytes) > 16 * 1024:
        return {}
    statement_kinds, _ = _fixed_literal_program_kinds(program, normalized)
    if statement_kinds is None:
        return {}
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
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
        return {}
    return {
        "schema": "factory.fixed-literal-program.v1",
        "disposition": "PROVEN_FIXED_LITERAL_PROGRAM",
        "source_path": source_path,
        "source_sha256": source_sha256,
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
    return (
        _workspace_namespace_hazard,
        _workspace_dynamic_exec_risk,
        _workspace_source_hashes,
        _fixed_literal_call,
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


class _LiteralConsumers:
    def __init__(
        self, root, snapshots, imports, audit, integrity, *, source_bytes, inventory
    ):
        self.root, self.trees, self.imports = root, snapshots, imports
        self.audit, self.integrity = audit, integrity
        self.parents, self.objects, self.refs = {}, {}, defaultdict(list)
        self.functions, self.methods, self.node_paths = {}, {}, {}
        self.fixture_cache, self.provider_cache = {}, {}
        self.app_fixture_cache = {}
        self.aliases, self.blocked, self.members = {}, set(), {}
        self.unmodeled_imports = []
        self.provider_closure = {}
        self.source_profiles = {}
        self.complete = True
        self.remaining_work = 1_000_000
        if (
            set(snapshots) != set(imports)
            or set(snapshots) != set(source_bytes)
            or not isinstance(inventory, dict)
            or set(snapshots) != set(inventory)
        ):
            self.complete = False
            return
        if (
            len(snapshots) > 2000
            or sum(map(len, source_bytes.values())) > 32 * 1024 * 1024
        ):
            self.complete = False
            return
        self.eligible = {path.resolve(): path for path in snapshots}
        self.aliases = {
            path: self.audit._module_security_aliases(tree)
            for path, tree in snapshots.items()
        }
        total = 0
        for path, tree in snapshots.items():
            raw = source_bytes[path]
            if inventory[path] != hashlib.sha256(raw).hexdigest():
                self.complete = False
                return
            if len(raw) > 1_000_000 or hashlib.sha256(raw).hexdigest() != getattr(
                tree, "_oracle_source_sha256", None
            ):
                self.complete = False
                return
            try:
                parsed = ast.parse(raw)
                if ast.dump(parsed, include_attributes=True) != ast.dump(
                    tree, include_attributes=True
                ):
                    self.complete = False
                    return
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                self.complete = False
                return
            nodes = []
            for node in self._walk(tree):
                total += 1
                if total > 200_000 or not self._tick(3):
                    self.complete = False
                    return
                nodes.append(node)
                self.node_paths[id(node)] = path
            self.parents.update(
                {id(c): n for n in nodes for c in ast.iter_child_nodes(n)}
            )
            self.integrity.bind_security_call_scopes(tree)
            self._objects(path, tree)
            self._bindings(path, nodes)
        self._bind_guarded_script_imports()
        self._references()
        self._reject_unmodeled_origins()
        self._provider_uses()

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
        for path, tree in self.trees.items():
            aliases = self.audit._module_security_aliases(
                ast.Module(
                    body=[
                        n
                        for n in self._walk(tree)
                        if isinstance(n, (ast.Import, ast.ImportFrom))
                    ],
                    type_ignores=[],
                )
            )
            for node in self._walk(tree):
                if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
                    continue
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
        self._scope_bindings(
            module, list(self._walk(self.trees[module])), set(staged), top
        )
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

    def _bindings(self, path, nodes):
        tree = self.trees[path]
        origins = (
            set(self.imports[path])
            | {name for p, name in self.objects if p == path}
            | {name for p, name in self.functions if p == path}
        )
        top = defaultdict(list)
        for statement in tree.body:
            if not self._tick():
                return
            for name in self.audit._bound_names(statement):
                top[name].append(statement)
        self.blocked.update((path, name) for name in origins if len(top[name]) != 1)
        self._scope_bindings(path, nodes, origins, top)
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

    def _scope_bindings(self, path, nodes, origins, top):
        for node in nodes:
            if not self._tick():
                return
            if (
                isinstance(node, ast.arg)
                and node.arg in origins
                and not self._fixture_parameter_value(path, node.arg, node)
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
        eligible = set(self.trees)
        for node in nodes:
            if isinstance(node, (ast.Import, ast.ImportFrom)) and node not in tree.body:
                view = self.audit._oracle_imports(
                    self.root, path, ast.Module(body=[node], type_ignores=[]), eligible
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
        for path, tree in self.trees.items():
            for node in self._walk(tree):
                if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
                    continue
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
        writes = [
            node
            for node in self._walk(scope)
            if isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ]
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
        for path, tree in self.trees.items():
            aliases = self.aliases[path]
            for name, origin in aliases.items():
                if (origin == module or origin.startswith(module + ".")) and (
                    path,
                    name,
                ) in self.blocked:
                    self.provider_cache[key] = False
                    return False
            for node in self._walk(tree):
                if (
                    isinstance(node, ast.Attribute)
                    and node.attr in attributes
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    and self.audit._resolved_ast_name(node.value, aliases)
                    in {module, *(module + "." + item for item in attributes)}
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
        if (
            not isinstance(node, ast.Dict)
            or not isinstance(parent, ast.Compare)
            or len(parent.ops) != 1
            or not isinstance(parent.ops[0], ast.Eq)
            or len(parent.comparators) != 1
        ):
            return False
        if parent.left is node:
            projection = parent.comparators[0]
        elif parent.comparators[0] is node:
            projection = parent.left
        else:
            return False
        assertion = self.parents.get(id(parent))
        function = self._containing_function(assertion)
        if (
            not isinstance(assertion, ast.Assert)
            or function is None
            or not isinstance(projection, ast.Subscript)
            or not isinstance(projection.value, ast.Name)
            or not isinstance(projection.slice, ast.Constant)
            or projection.slice.value != "detail"
        ):
            return False
        data_name = projection.value.id
        data_assignment = self._unique_name_assignment(function, data_name)
        if (
            not isinstance(data_assignment, ast.Assign)
            or data_assignment not in function.body
        ):
            return False
        cast_call = data_assignment.value
        if (
            not isinstance(cast_call, ast.Call)
            or not isinstance(cast_call.func, (ast.Name, ast.Attribute))
            or self.audit._resolved_ast_name(cast_call.func, self.aliases[path])
            != "typing.cast"
            or len(cast_call.args) != 2
            or cast_call.keywords
        ):
            return False
        response_call = cast_call.args[1]
        if (
            not isinstance(response_call, ast.Call)
            or not isinstance(response_call.func, ast.Attribute)
            or response_call.func.attr != "json"
            or response_call.args
            or response_call.keywords
            or not isinstance(response_call.func.value, ast.Name)
        ):
            return False
        response_name = response_call.func.value.id
        response_assignment = self._unique_name_assignment(function, response_name)
        if (
            not isinstance(response_assignment, ast.Assign)
            or response_assignment not in function.body
        ):
            return False
        request = response_assignment.value
        if (
            not isinstance(request, ast.Await)
            or not isinstance(request.value, ast.Call)
            or not isinstance(request.value.func, ast.Attribute)
            or request.value.func.attr not in {"get", "post"}
            or not isinstance(request.value.func.value, ast.Name)
        ):
            return False
        return (
            self._request_client_origin(path, function, request)
            and self._provider_is_unmodified("typing", {"cast"})
            and self._json_assertion_values(
                path, function, node, data_name, response_name
            )
        )

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
        return bool(
            origin
            and origin[0] == "class"
            and len(origin[3]) == 1
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
            if not self._tick():
                return
            yield child

    def _tick(self, amount=1):
        self.remaining_work -= amount
        if self.remaining_work < 0:
            self.complete = False
        return self.complete
