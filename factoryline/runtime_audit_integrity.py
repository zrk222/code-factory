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
        call_name != "exec" or not isinstance(node, ast.Call)
        or not isinstance(node.func, ast.Name) or node.func.id != "exec"
        or len(node.args) != 3 or node.keywords
        or not isinstance(node.args[0], ast.Constant)
        or type(node.args[0].value) is not str
        or not isinstance(node.args[1], ast.Name)
        or not isinstance(node.args[2], ast.Constant) or node.args[2].value is not None
    ):
        return None
    import keyword

    match = re.fullmatch(r"type ([A-Za-z][A-Za-z0-9_]*) = int", node.args[0].value)
    if not match or keyword.iskeyword(match[1]) or match[1] in {"type", "int"}:
        return None
    return match[1]


def _closed_declaration_namespace(tree, call, alias):
    scope = next((fn for fn in ast.walk(tree)
                  if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
                  and any(isinstance(s, ast.Expr) and s.value is call for s in fn.body)), None)
    if scope is None:
        return False
    name = call.args[1].id
    assignments = [s for s in scope.body if isinstance(s, (ast.Assign, ast.AnnAssign))
                   and isinstance(s.value, ast.Dict) and not s.value.keys
                   and ((isinstance(s, ast.Assign) and len(s.targets) == 1
                         and isinstance(s.targets[0], ast.Name) and s.targets[0].id == name)
                        or (isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name)
                            and s.target.id == name))]
    if len(assignments) != 1 or assignments[0].lineno >= call.lineno:
        return False
    target = assignments[0].targets[0] if isinstance(assignments[0], ast.Assign) else assignments[0].target
    if any(name in _oracle_bound_names(s) for s in scope.body if s is not assignments[0]):
        return False
    parents = {child: parent for parent in ast.walk(scope) for child in ast.iter_child_nodes(parent)}
    for item in ast.walk(scope):
        if isinstance(item, ast.arg) and item.arg == name:
            return False
        if isinstance(item, (ast.Global, ast.Nonlocal)) and name in item.names:
            return False
        if not isinstance(item, ast.Name) or item.id != name or item is target or item is call.args[1]:
            continue
        parent = parents.get(item)
        if not (item.lineno > call.lineno and isinstance(parent, ast.Subscript)
                and parent.value is item and isinstance(parent.ctx, ast.Load)
                and isinstance(parent.slice, ast.Constant) and parent.slice.value == alias):
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
            if name in {"exec", "eval", "__builtins__", "globals", "locals", "vars", "setattr", "delattr"} or name == "int" and (
                isinstance(item, ast.arg) or isinstance(item.ctx, (ast.Store, ast.Del))
            ):
                return False
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and item.name in {"exec", "int"}:
            return False
        if isinstance(item, (ast.Import, ast.ImportFrom)) and any(
            (a.asname or a.name.split(".")[0]) in {"exec", "int"} or a.name == "*" for a in item.names
        ):
            return False
        if isinstance(item, ast.ImportFrom) and item.module == "builtins" and any(
            a.name in {"exec", "eval", "setattr", "delattr", "__dict__", "__builtins__", "globals", "locals", "vars"}
            for a in item.names
        ):
            return False
        if isinstance(item, ast.Attribute) and (item.attr in {"exec", "eval", "__dict__", "__builtins__", "__setattr__", "__delattr__", "setattr", "delattr"} or item.attr == "int" and isinstance(item.ctx, (ast.Store, ast.Del))):
            return False
    return True


def closed_declaration_input_witness(node, call_name, *, source_bytes, source_path):
    """Recognize fixed Python 3.12 alias input without compiling or executing it."""
    if not isinstance(source_bytes, bytes) or not isinstance(source_path, str) or not source_path:
        return {}
    alias = _closed_declaration_program(node, call_name)
    if alias is None:
        return {}
    try:
        tree = ast.parse(source_bytes)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return {}
    def span(n):
        return [getattr(n, k, None) for k in ("lineno", "col_offset", "end_lineno", "end_col_offset")]
    matches = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and span(n) == span(node)]
    if len(matches) != 1 or ast.dump(matches[0]) != ast.dump(node):
        return {}
    call = matches[0]
    if not _closed_declaration_binding(tree, call) or not _closed_declaration_namespace(tree, call, alias):
        return {}
    return {
        "schema": "factory.closed-declaration-input.v1",
        "disposition": "PROVEN_CLOSED_DECLARATION_INPUT",
        "source_path": source_path,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "call_span": span(call), "literal_span": span(call.args[0]),
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
        self.aliases, self.blocked, self.members = {}, set(), {}
        self.unmodeled_imports = []
        self.provider_closure = {}
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
            self.parents.update(
                {id(c): n for n in nodes for c in ast.iter_child_nodes(n)}
            )
            self.aliases[path] = self.audit._module_security_aliases(tree)
            self.integrity.bind_security_call_scopes(tree)
            self._objects(path, tree)
            self._bindings(path, nodes)
        self._references()
        self._reject_unmodeled_origins()
        self._provider_uses()

    def _objects(self, path, tree):
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                self.objects[path, node.name] = node
                for item in node.body:
                    if not isinstance(item, (ast.Assign, ast.AnnAssign)):
                        continue
                    targets = (
                        item.targets if isinstance(item, ast.Assign) else [item.target]
                    )
                    for target in targets:
                        if (
                            isinstance(target, ast.Name)
                            and self.audit._SECRET_ASSIGNMENT.search(target.id)
                            and self.audit._credential_role_witness(
                                item, target, self.aliases[path]
                            )
                        ):
                            self.members[path, node.name, target.id] = item
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                if len(targets) == 1 and isinstance(targets[0], ast.Name):
                    self.objects[path, targets[0].id] = node.value

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

    def _bindings(self, path, nodes):
        tree = self.trees[path]
        origins = set(self.imports[path]) | {
            name for p, name in self.objects if p == path
        }
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
            if isinstance(node, ast.arg) and node.arg in origins:
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
        if obj is not None:
            if isinstance(obj, (ast.Name, ast.Attribute)):
                return self.resolve(
                    path, (*self.audit._name(obj).split("."), *tail), seen
                )
            return "value", path, name, tuple(tail)
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
                if not isinstance(parent, ast.Attribute):
                    return False
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
        return True

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
        return self._public_assertion(path, node, parent)

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

    def _public_assertion(self, path, node, parent):
        if isinstance(parent, ast.Compare):
            if not all(
                part is node
                or isinstance(part, ast.Constant)
                and type(part.value) in {str, bytes, int, float, bool, type(None)}
                for part in [parent.left, *parent.comparators]
            ):
                return False
            parent = self.parents.get(id(parent))
        if isinstance(parent, ast.Assert):
            relative = path.relative_to(self.root)
            return "tests" in relative.parts or relative.name.startswith("test_")
        return False

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
