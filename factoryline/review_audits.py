"""Read-only Python pattern and guard-path audits; never release authority.

These are bounded syntactic analyses, not a symbolic executor or a security
certification. A declared guard must raise on denial and must not be rebound.
"""

from __future__ import annotations

import ast
import configparser
from collections import OrderedDict
from dataclasses import dataclass
from hashlib import sha256
from fnmatch import fnmatchcase
import json
import operator
import os
from pathlib import Path, PureWindowsPath
import re
import sys
from threading import RLock
import time
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib
from .audit_action_refs import (
    audit_remediation_packet,
    _security_scan_report_candidate_payload,
    _security_scan_coverage,
    _security_scan_state,
    _security_scan_action_summary,
)
from .deep_audit_io import local_file
from .ops_telemetry import _measure_hash, _measure_parse
from .runtime_audit_common import RuntimeAuditError, runtime_config_sources
from . import review_integrity as integrity, intent_quality as contracts
from .review_integrity import security_call_name as security_call_name

_completion_only_oracle = integrity._completion_only_oracle

SCHEMA = "factory.review-audit-policy.v1"
FINGERPRINT_SCHEMA = "factory.code-review-fingerprint.v1"
SECURITY_SCHEMA = "factory.security-audit.v1"
TENANT_CONTRACT_SCHEMA = "factory.tenant-read-contract.v1"
MAX_SECURITY_SOURCE_FILES = 460
MAX_BYTES = 1_000_000
MAX_RULES = 128
MAX_PATHS = 64
MAX_ORACLE_CONTEXT_CACHE_ENTRIES = 16
MAX_ORACLE_CONTEXT_CACHE_BYTES = 4 * 1024 * 1024
ORACLE_CONTEXT_CACHE_TTL_SECONDS = 300
_ORACLE_CONTEXT_CACHE: OrderedDict[str, tuple[str, int, float]] = OrderedDict()
_ORACLE_CONTEXT_CACHE_BYTES = 0
_ORACLE_CONTEXT_CACHE_HITS = 0
_ORACLE_CONTEXT_CACHE_MISSES = 0
_ORACLE_CONTEXT_CACHE_LOCK = RLock()
ORIGINS = {"human_confirmed", "trusted_source", "observed_production", "agent_proposed"}
NAME = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")


def _oracle_context_cache_clear() -> None:
    """Clear process-local projected oracle contexts and counters."""
    global _ORACLE_CONTEXT_CACHE_BYTES, _ORACLE_CONTEXT_CACHE_HITS
    global _ORACLE_CONTEXT_CACHE_MISSES
    with _ORACLE_CONTEXT_CACHE_LOCK:
        _ORACLE_CONTEXT_CACHE.clear()
        _ORACLE_CONTEXT_CACHE_BYTES = 0
        _ORACLE_CONTEXT_CACHE_HITS = 0
        _ORACLE_CONTEXT_CACHE_MISSES = 0


def _oracle_context_cache_info() -> dict[str, int]:
    with _ORACLE_CONTEXT_CACHE_LOCK:
        return {
            "entries": len(_ORACLE_CONTEXT_CACHE),
            "serialized_bytes": _ORACLE_CONTEXT_CACHE_BYTES,
            "hits": _ORACLE_CONTEXT_CACHE_HITS,
            "misses": _ORACLE_CONTEXT_CACHE_MISSES,
        }


def _oracle_context_cache_read(key: str) -> tuple[dict, list] | None:
    from .review_integrity import decode_structural_context

    global _ORACLE_CONTEXT_CACHE_BYTES, _ORACLE_CONTEXT_CACHE_HITS
    global _ORACLE_CONTEXT_CACHE_MISSES
    with _ORACLE_CONTEXT_CACHE_LOCK:
        if (cached := _ORACLE_CONTEXT_CACHE.get(key)) is None:
            _ORACLE_CONTEXT_CACHE_MISSES += 1
            return None
        payload, size, created = cached
        if time.monotonic() - created > ORACLE_CONTEXT_CACHE_TTL_SECONDS:
            _ORACLE_CONTEXT_CACHE.pop(key, None)
            _ORACLE_CONTEXT_CACHE_BYTES -= size
            _ORACLE_CONTEXT_CACHE_MISSES += 1
            return None
        _ORACLE_CONTEXT_CACHE.move_to_end(key)
    try:
        if not integrity.NativeOraclePayload.valid(payload, key):
            raise ValueError("oracle cache payload is not native or current")
        document = json.loads(payload)
        contexts = {
            Path(item["path"]): {
                "helpers": set(item["helpers"]),
                "weak_helpers": set(item["weak_helpers"]),
                "mixins": set(item["mixins"]),
                "pytest_inherited": set(item["pytest_inherited"]),
                "click_runners": set(item["click_runners"]),
                "typecheck": item["typecheck"],
                "flask_apps": set(item.get("flask_apps", [])),
                "callback_invokers": item.get("callback_invokers", {}),
                "codspeed_benchmark": item.get("codspeed_benchmark", False),
                "async_runner_fixtures": item.get("async_runner_fixtures", {}),
                "mock_fixture_provenance": item.get("mock_fixture_provenance", {}),
                "protocol_observations": item.get("protocol_observations", {}),
                "fixed_program_workspace": item.get("fixed_program_workspace", {}),
                **decode_structural_context(item.get("structural_context", {})),
            }
            for item in document["contexts"]
        }
        edges = document["edges"]
        with _ORACLE_CONTEXT_CACHE_LOCK:
            _ORACLE_CONTEXT_CACHE_HITS += 1
        return contexts, edges
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        with _ORACLE_CONTEXT_CACHE_LOCK:
            removed = _ORACLE_CONTEXT_CACHE.pop(key, None)
            if removed is not None:
                _ORACLE_CONTEXT_CACHE_BYTES -= removed[1]
            _ORACLE_CONTEXT_CACHE_MISSES += 1
        return None


def _oracle_context_cache_write(key: str, contexts: dict, edges: list) -> None:
    from .review_integrity import encode_structural_context

    global _ORACLE_CONTEXT_CACHE_BYTES
    rows = []
    for path, context in sorted(contexts.items(), key=lambda item: str(item[0])):
        rows.append(
            {
                "path": path.as_posix(),
                "helpers": sorted(context["helpers"]),
                "weak_helpers": sorted(context["weak_helpers"]),
                "mixins": sorted(context["mixins"]),
                "pytest_inherited": sorted(context["pytest_inherited"]),
                "click_runners": sorted(context["click_runners"]),
                "typecheck": bool(context["typecheck"]),
                "flask_apps": sorted(context.get("flask_apps", set())),
                "callback_invokers": context.get("callback_invokers", {}),
                "codspeed_benchmark": context.get("codspeed_benchmark", False),
                "async_runner_fixtures": context.get("async_runner_fixtures", {}),
                "mock_fixture_provenance": context.get("mock_fixture_provenance", {}),
                "protocol_observations": context.get("protocol_observations", {}),
                "fixed_program_workspace": context.get("fixed_program_workspace", {}),
                "structural_context": encode_structural_context(context),
            }
        )
    document = {"contexts": rows, "edges": edges}
    payload = integrity.NativeOraclePayload(
        json.dumps(document, sort_keys=True, separators=(",", ":")), key
    )
    size = len(payload.encode("utf-8")) + len(key) + 32
    with _ORACLE_CONTEXT_CACHE_LOCK:
        if size > MAX_ORACLE_CONTEXT_CACHE_BYTES:
            return
        previous = _ORACLE_CONTEXT_CACHE.pop(key, None)
        if previous is not None:
            _ORACLE_CONTEXT_CACHE_BYTES -= previous[1]
        _ORACLE_CONTEXT_CACHE[key] = (payload, size, time.monotonic())
        _ORACLE_CONTEXT_CACHE_BYTES += size
        while (
            len(_ORACLE_CONTEXT_CACHE) > MAX_ORACLE_CONTEXT_CACHE_ENTRIES
            or _ORACLE_CONTEXT_CACHE_BYTES > MAX_ORACLE_CONTEXT_CACHE_BYTES
        ):
            _, (_, removed_bytes, _) = _ORACLE_CONTEXT_CACHE.popitem(last=False)
            _ORACLE_CONTEXT_CACHE_BYTES -= removed_bytes


class ReviewAuditError(ValueError):
    code = "E_REVIEW_AUDIT_INPUT"


def _unique_fields(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReviewAuditError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def _relative_path(path: str) -> Path:
    if not isinstance(path, str) or not path or "\\" in path:
        raise ReviewAuditError("Use a nonempty workspace-relative POSIX path.")
    relative = Path(path)
    if relative.is_absolute() or PureWindowsPath(path).drive or ".." in relative.parts:
        raise ReviewAuditError(f"Path escapes workspace: {path}")
    return relative


def _read(root: Path, path: str) -> tuple[bytes, dict]:
    relative = _relative_path(path)
    resolved = (root / relative).resolve()
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ReviewAuditError(f"Missing or escaping file: {path}")
    if resolved.stat().st_size > MAX_BYTES:
        raise ReviewAuditError(f"File exceeds {MAX_BYTES} bytes: {path}")
    with resolved.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if not data or len(data) > MAX_BYTES:
        raise ReviewAuditError(f"Empty or oversized file: {path}")
    return data, {
        "path": relative.as_posix(),
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
    }


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _body_nodes(node: ast.AST):
    """Nested functions/classes/lambdas are not calls in the inspected body."""
    yield node
    if isinstance(
        node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
    ):
        return
    for child in ast.iter_child_nodes(node):
        yield from _body_nodes(child)


def _iter_ast_nodes(node: ast.AST):
    """Walk one AST without allocating or repeating ``ast.walk`` inventories."""
    pending = [node]
    while pending:
        child = pending.pop()
        yield child
        pending.extend(ast.iter_child_nodes(child))


def _calls(body: list[ast.stmt]) -> set[str]:
    return {
        _name(node.func)
        for stmt in body
        for node in _body_nodes(stmt)
        if isinstance(node, ast.Call)
    } - {""}


def _symbol(tree: ast.Module, symbol: str):
    body = tree.body
    selected = None
    for part in symbol.split("."):
        matches = [
            node
            for node in body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == part
        ]
        if len(matches) != 1:
            raise ReviewAuditError(f"Missing or ambiguous symbol: {symbol}")
        selected = matches[0]
        body = selected.body
    if not isinstance(selected, _FUNCTION_NODES):
        raise ReviewAuditError(f"Target is not a function: {symbol}")
    return selected


def _target(root: Path, value: Any, cache: dict):
    if not isinstance(value, dict) or set(value) != {"path", "symbol"}:
        raise ReviewAuditError("Target requires exactly path and symbol.")
    path, symbol = value["path"], value["symbol"]
    if (
        not isinstance(path, str)
        or not path.endswith(".py")
        or not isinstance(symbol, str)
        or not NAME.fullmatch(symbol)
    ):
        raise ReviewAuditError(
            "Targets require a Python file and qualified function symbol."
        )
    if path not in cache:
        if len(cache) >= 64:
            raise ReviewAuditError(
                "At most 64 source files may be inspected per policy."
            )
        data, binding = _read(root, path)
        tree = ast.parse(data, filename=path)
        if sum(1 for _ in ast.walk(tree)) > 10000:
            raise ReviewAuditError(f"AST node limit exceeded: {path}")
        cache[path] = (tree, binding)
    node = _symbol(cache[path][0], symbol)
    return {"path": cache[path][1]["path"], "symbol": symbol, "line": node.lineno}, node


def _rule(value: Any, seen: set[str], fields: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != fields | {"id", "origin"}:
        raise ReviewAuditError("Rule contains missing or unknown fields.")
    identifier, origin = value["id"], value["origin"]
    if not isinstance(identifier, str) or not identifier.strip() or identifier in seen:
        raise ReviewAuditError("Rule IDs must be nonempty and unique.")
    if not isinstance(origin, str) or origin not in ORIGINS:
        raise ReviewAuditError("Unknown rule provenance.")
    seen.add(identifier)
    return value


def _call_names(values: Any) -> list[str]:
    if not isinstance(values, list) or not 1 <= len(values) <= 32:
        raise ReviewAuditError("Declare between 1 and 32 call names.")
    if any(not isinstance(v, str) or not NAME.fullmatch(v) for v in values) or len(
        set(values)
    ) != len(values):
        raise ReviewAuditError("Call names must be unique dotted identifiers.")
    return values


def _finding(code: str, rule: dict, target: dict, message: str, **facts) -> dict:
    return {
        "code": code,
        "rule_id": rule["id"],
        "declared_origin": rule["origin"],
        "target": target,
        "message": message,
        "facts": facts,
        "severity": "review",
    }


def _patterns(rule: dict, members: list, calls: list[str]) -> dict:
    inspected = [
        {**target, "calls": sorted(_calls(node.body))} for target, node in members
    ]
    findings = []
    for target in inspected:
        for call in calls:
            if call not in target["calls"]:
                peers = [
                    {"path": p["path"], "symbol": p["symbol"]}
                    for p in inspected
                    if call in p["calls"]
                ]
                findings.append(
                    _finding(
                        "PATTERN_REQUIRED_CALL_MISSING",
                        rule,
                        target,
                        f"{target['symbol']} has no direct-body call to {call}.",
                        missing_call=call,
                        peers_with_call=peers,
                    )
                )
    return {
        "rule_id": rule["id"],
        "tool": "patterns",
        "state": "findings" if findings else "no_structural_findings",
        "members": inspected,
        "findings": findings,
    }


@dataclass(frozen=True)
class _Path:
    guarded: bool = False
    branches: tuple[str, ...] = ()


class _GuardPaths:
    def __init__(self, rule: dict, target: dict):
        self.rule, self.target = rule, target
        self.guard, self.effect = rule["guard_call"], rule["effect_call"]
        self.findings: list[dict] = []
        self.gaps: set[str] = set()
        self.effects = 0
        self.steps = 0

    def expressions(self, node: ast.AST, paths: list[_Path]) -> None:
        """Collect conservative effect witnesses without promoting expression guards."""
        # Presence below expressions is conservative: no expression call establishes
        # a guard. Short-circuit, comprehensions, lambdas and rebinding need review.
        nodes = list(_body_nodes(node))
        for item in nodes:
            if isinstance(
                item,
                (ast.BoolOp, ast.IfExp, ast.comprehension, ast.Lambda, ast.NamedExpr),
            ):
                self.gaps.add(
                    f"expression semantics at line {item.lineno if hasattr(item, 'lineno') else node.lineno}"
                )
            if isinstance(item, ast.Call) and _name(item.func) == self.effect:
                self.effects += 1
                for path in paths:
                    if not path.guarded:
                        self.findings.append(
                            _finding(
                                "GUARD_PATH_BYPASS",
                                self.rule,
                                self.target,
                                f"{self.effect} at line {item.lineno} can precede the declared guard statement.",
                                effect_line=item.lineno,
                                guard_call=self.guard,
                                effect_call=self.effect,
                                structural_witness=list(path.branches),
                            )
                        )
            if isinstance(item, ast.Call) and _name(item.func) in {
                "exec",
                "eval",
                "setattr",
                "delattr",
                "globals",
                "locals",
                "__import__",
            }:
                self.gaps.add(f"dynamic code or binding at line {item.lineno}")

    def block(
        self, body: list[ast.stmt], paths: list[_Path], depth: int = 0
    ) -> list[_Path]:
        """Walk sequential statements with explicit exploration budgets."""
        if depth > 32:
            self.gaps.add("branch depth limit")
            return []
        for stmt in body:
            self.steps += len(paths)
            if self.steps > 4096 or len(paths) > MAX_PATHS:
                self.gaps.add("path exploration limit")
                return []
            if not paths:
                break
            paths = self.statement(stmt, paths, depth)
        return paths

    def statement(self, stmt: ast.stmt, paths: list[_Path], depth: int) -> list[_Path]:
        """Branch supported statements and retain unsupported semantics as gaps."""
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.gaps.add(
                f"nested definition/decorator semantics at line {stmt.lineno}"
            )
            return paths
        if isinstance(stmt, ast.If):
            self.expressions(stmt.test, paths)
            yes = [
                _Path(p.guarded, p.branches + (f"line {stmt.lineno}: condition true",))
                for p in paths
            ]
            no = [
                _Path(p.guarded, p.branches + (f"line {stmt.lineno}: condition false",))
                for p in paths
            ]
            return self.block(stmt.body, yes, depth + 1) + self.block(
                stmt.orelse, no, depth + 1
            )
        supported = (
            ast.Expr,
            ast.Assign,
            ast.AnnAssign,
            ast.Return,
            ast.Raise,
            ast.Pass,
        )
        if not isinstance(stmt, supported):
            self.gaps.add(f"unsupported {type(stmt).__name__} at line {stmt.lineno}")
            self.expressions(stmt, [_Path(False, p.branches) for p in paths])
            return [_Path(False, p.branches) for p in paths]
        return self.simple_statement(stmt, paths)

    def simple_statement(self, stmt: ast.stmt, paths: list[_Path]) -> list[_Path]:
        """Check effects before advancing an unconditional guard on live paths."""
        self.expressions(stmt, paths)
        if isinstance(stmt, (ast.Return, ast.Raise)):
            return []
        if self.rebinds_identity(stmt):
            self.gaps.add(f"call identity assignment at line {stmt.lineno}")
            return [_Path(False, p.branches) for p in paths]
        expr = stmt.value if isinstance(stmt, ast.Expr) else None
        expr = expr.value if isinstance(expr, ast.Await) else expr
        if isinstance(expr, ast.Call) and _name(expr.func) == self.guard:
            return [_Path(True, p.branches) for p in paths]
        return paths

    def rebinds_identity(self, stmt: ast.stmt) -> bool:
        """Detect local assignment that invalidates the declared call identity."""
        if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            return False
        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
        roots = {self.guard.split(".")[0], self.effect.split(".")[0]}
        names = {
            n.id
            for target in targets
            for n in ast.walk(target)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
        }
        return bool(names & roots) or any(isinstance(t, ast.Attribute) for t in targets)

    def analyze(self, node: ast.AST) -> dict:
        """Return findings and coverage gaps for one declared function body."""
        if node.decorator_list:
            self.gaps.add("decorator runtime semantics not analyzed")
        roots = {self.guard.split(".")[0], self.effect.split(".")[0]}
        if any(
            arg.arg in roots for arg in ast.walk(node.args) if isinstance(arg, ast.arg)
        ):
            self.gaps.add("call identity shadowed by parameter")
        self.block(node.body, [_Path()])
        if not self.effects:
            self.gaps.add("declared effect not observed on analyzed paths")
        unique = {json.dumps(f, sort_keys=True): f for f in self.findings}
        return {
            "rule_id": self.rule["id"],
            "tool": "guard-paths",
            "target": self.target,
            "state": "incomplete"
            if self.gaps
            else "findings"
            if unique
            else "no_structural_findings",
            "findings": list(unique.values()),
            "analysis_gaps": sorted(self.gaps),
            "effect_occurrences": self.effects,
        }


def _policy_parts(policy: dict) -> tuple[list, list]:
    if (
        not isinstance(policy, dict)
        or set(policy) != {"schema", "pattern_groups", "effect_rules"}
        or policy["schema"] != SCHEMA
    ):
        raise ReviewAuditError("Invalid review audit policy schema or fields.")
    groups, effects = policy["pattern_groups"], policy["effect_rules"]
    if (
        not isinstance(groups, list)
        or not isinstance(effects, list)
        or not 1 <= len(groups) + len(effects) <= MAX_RULES
    ):
        raise ReviewAuditError(f"Policy requires 1..{MAX_RULES} rules.")
    return groups, effects


def _prepare_pattern(
    root: Path, value: dict, cache: dict, seen: set[str]
) -> tuple[dict, list, set[str]]:
    rule = _rule(value, seen, {"members", "required_calls"})
    calls = _call_names(rule["required_calls"])
    if not isinstance(rule["members"], list) or not 2 <= len(rule["members"]) <= 32:
        raise ReviewAuditError("Pattern groups require 2..32 peers.")
    members = [_target(root, item, cache) for item in rule["members"]]
    if len({(target["path"], target["symbol"]) for target, _ in members}) != len(
        members
    ):
        raise ReviewAuditError("Duplicate peer target.")
    return rule, members, calls


def _prepare_effect(root: Path, value: dict, cache: dict, seen: set[str]) -> tuple:
    rule = _rule(value, seen, {"target", "guard_call", "effect_call"})
    _call_names([rule["guard_call"], rule["effect_call"]])
    target, node = _target(root, rule["target"], cache)
    return rule, target, node


def _prepare(root: Path, policy: dict, cache: dict) -> tuple[list, list]:
    groups, effects = _policy_parts(policy)
    seen: set[str] = set()
    patterns = [_prepare_pattern(root, value, cache, seen) for value in groups]
    guards = [_prepare_effect(root, value, cache, seen) for value in effects]
    return patterns, guards


def _run(patterns: list, guards: list, tool: str) -> list:
    results = (
        [_patterns(*args) for args in patterns] if tool in {"all", "patterns"} else []
    )
    if tool in {"all", "guard-paths"}:
        results.extend(
            _GuardPaths(rule, target).analyze(node) for rule, target, node in guards
        )
    return results


def _receipt(tool: str, bindings: list, results: list) -> dict:
    covered_tools = {r["tool"] for r in results}
    required_tools = {"patterns", "guard-paths"} if tool == "all" else {tool}
    missing = sorted(required_tools - covered_tools)
    findings = [f for r in results for f in r["findings"]]
    incomplete = bool(missing) or any(r["state"] == "incomplete" for r in results)
    core = {
        "schema": "factory.code-review-audits.v1",
        "tool": tool,
        "state": "incomplete"
        if incomplete
        else "findings"
        if findings
        else "no_structural_findings",
        "policy": bindings[0],
        "sources": bindings[1:],
        "results": results,
        "findings": findings,
        "unconfigured_tools": missing,
        "governance": "human_controlled",
        "authority": {
            "execution": False,
            "approval": False,
            "publication": False,
            "deployment": False,
        },
        "limits": [
            "Python declared symbols only; no whole-repository coverage claim.",
            "Peer agreement is not correctness; provenance is declared, not authenticated.",
            "Guard-path witnesses are syntactic, not proven runtime reachability.",
            "Assumes a direct guard raises on denial; no interprocedural, alias, exception or concurrency proof.",
        ],
    }
    return {
        **core,
        "audit_sha256": sha256(json.dumps(core, sort_keys=True).encode()).hexdigest(),
    }


def audit_code(
    root: Path, policy_path: str = ".factory/review-audits.json", *, tool: str = "all"
) -> dict:
    """Inspect declared source without importing it, running commands or writing it."""
    if not isinstance(tool, str) or tool not in {"all", "patterns", "guard-paths"}:
        raise ReviewAuditError("Unknown audit tool.")
    workspace = Path(root).resolve()
    cache: dict = {}
    try:
        data, policy_binding = _read(workspace, policy_path)
        patterns, guards = _prepare(
            workspace, json.loads(data, object_pairs_hook=_unique_fields), cache
        )
        results = _run(patterns, guards, tool)
        bindings = [policy_binding] + [cache[path][1] for path in sorted(cache)]
        if any(_read(workspace, item["path"])[1] != item for item in bindings):
            raise ReviewAuditError("Evidence changed during analysis.")
    except (OSError, UnicodeError, SyntaxError, RecursionError, ValueError) as exc:
        raise ReviewAuditError(str(exc)) from exc
    return _receipt(tool, bindings, results)


def _fingerprint_payload(audit: dict) -> dict:
    """Reduce one audit to stable, content-addressed facts for cross-run comparison."""
    results = []
    for result in audit.get("results", []):
        results.append(
            {
                "rule_id": result.get("rule_id"),
                "tool": result.get("tool"),
                "state": result.get("state"),
                "finding_codes": sorted(
                    str(item.get("code"))
                    for item in result.get("findings", [])
                    if isinstance(item, dict)
                ),
                "analysis_gaps": sorted(
                    str(item) for item in result.get("analysis_gaps", [])
                ),
            }
        )
    return {
        "schema": FINGERPRINT_SCHEMA,
        "policy_sha256": audit["policy"]["sha256"],
        "sources": sorted(
            (
                {"path": item["path"], "sha256": item["sha256"], "bytes": item["bytes"]}
                for item in audit["sources"]
            ),
            key=lambda item: item["path"],
        ),
        "results": sorted(
            results, key=lambda item: (str(item["tool"]), str(item["rule_id"]))
        ),
        "state": audit["state"],
        "finding_codes": sorted(
            str(item.get("code"))
            for item in audit.get("findings", [])
            if isinstance(item, dict)
        ),
    }


def _self_hash(value: dict, field: str) -> str:
    body = {key: item for key, item in value.items() if key != field}
    return sha256(
        json.dumps(
            body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def _read_fingerprint(path: Path) -> dict:
    """Read and validate a previously emitted fingerprint without trusting its labels."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReviewAuditError(f"Invalid audit fingerprint: {path}") from exc
    if not isinstance(value, dict) or value.get("schema") != FINGERPRINT_SCHEMA:
        raise ReviewAuditError("Baseline is not a Code-Factory audit fingerprint.")
    if not isinstance(value.get("fingerprint"), dict) or value.get(
        "fingerprint_sha256"
    ) != _self_hash(value["fingerprint"], "fingerprint_sha256"):
        raise ReviewAuditError("Baseline fingerprint digest is invalid.")
    if value.get("receipt_sha256") != _self_hash(value, "receipt_sha256"):
        raise ReviewAuditError("Baseline receipt digest is invalid.")
    return value


def _write_fingerprint(root: Path, path: Path, value: dict) -> None:
    """Write only to an explicit workspace-contained path."""
    workspace = root.resolve()
    destination = path if path.is_absolute() else workspace / path
    destination = destination.resolve()
    if not destination.is_relative_to(workspace):
        raise ReviewAuditError("Fingerprint output must remain inside the workspace.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _fingerprint_baseline_file(workspace: Path, baseline_path: Path) -> Path:
    """Resolve baseline evidence without allowing a path outside the workspace."""
    baseline_file = (
        (workspace / baseline_path).resolve()
        if not baseline_path.is_absolute()
        else baseline_path.resolve()
    )
    if not baseline_file.is_relative_to(workspace):
        raise ReviewAuditError("Baseline fingerprint must remain inside the workspace.")
    return baseline_file


def _fingerprint_changes(before: dict, fingerprint: dict) -> dict:
    """Compare policy, source, result, and finding identities independently."""
    return {
        "policy": before.get("policy_sha256") != fingerprint["policy_sha256"],
        "sources": before.get("sources") != fingerprint["sources"],
        "results": (
            before.get("results") != fingerprint["results"]
            or before.get("state") != fingerprint["state"]
        ),
        "finding_codes": {
            "added": sorted(
                set(fingerprint["finding_codes"]) - set(before.get("finding_codes", []))
            ),
            "removed": sorted(
                set(before.get("finding_codes", [])) - set(fingerprint["finding_codes"])
            ),
        },
    }


def _classify_fingerprint_changes(result: dict) -> None:
    """Fail closed when stable inputs yield contradictory results or drift."""
    changes = result["changes"]
    if not changes["policy"] and not changes["sources"] and changes["results"]:
        result.update(
            marker="AUDIT_FINGERPRINT_CONTRADICTORY",
            state="CONTRADICTORY",
            reusable=False,
            code="E_AUDIT_RESULT_CONTRADICTION",
            action_summary="Block reuse: identical policy and source bytes produced different audit results.",
        )
    elif changes["policy"] or changes["sources"]:
        result.update(
            marker="AUDIT_FINGERPRINT_DRIFT",
            state="DRIFT_DETECTED",
            reusable=False,
            code="E_AUDIT_FINGERPRINT_STALE",
            action_summary="Do not reuse the baseline: policy or audited source bytes changed; run a fresh review.",
        )
    else:
        result["action_summary"] = (
            "Baseline and current audit are byte-identical; reuse is content-addressed and still non-authorizing."
        )


def audit_fingerprint(
    root: Path,
    policy_path: str = ".factory/review-audits.json",
    *,
    baseline_path: Path | None = None,
    out_path: Path | None = None,
) -> dict:
    """Produce a deterministic audit fingerprint and fail closed on stale or contradictory reuse."""
    workspace = Path(root).resolve()
    try:
        audit = audit_code(workspace, policy_path, tool="all")
        fingerprint = _fingerprint_payload(audit)
        result: dict[str, Any] = {
            "schema": FINGERPRINT_SCHEMA,
            "marker": "AUDIT_FINGERPRINT_READY",
            "state": "CURRENT",
            "reusable": True,
            "fingerprint": fingerprint,
            "fingerprint_sha256": _self_hash(fingerprint, "fingerprint_sha256"),
            "changes": {
                "policy": False,
                "sources": False,
                "results": False,
                "finding_codes": {"added": [], "removed": []},
            },
            "authority": {
                "execution": False,
                "approval": False,
                "publication": False,
                "deployment": False,
            },
            "claim_boundary": "Fresh local structural audit fingerprint only; no runtime correctness, security certification, or release authority.",
        }
        if baseline_path is not None:
            baseline = _read_fingerprint(
                _fingerprint_baseline_file(workspace, baseline_path)
            )
            result["changes"] = _fingerprint_changes(
                baseline["fingerprint"], fingerprint
            )
            _classify_fingerprint_changes(result)
        else:
            result["action_summary"] = (
                "Created a fresh content-addressed audit fingerprint; no baseline comparison was requested."
            )
        result["receipt_sha256"] = _self_hash(result, "receipt_sha256")
        if out_path is not None:
            _write_fingerprint(workspace, out_path, result)
        return result
    except ReviewAuditError:
        raise
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        raise ReviewAuditError(str(exc)) from exc


_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|password|private[_-]?key|secret)"
)
_PLACEHOLDER_SECRET = re.compile(
    r"(?i)^(?:$|changeme|replace[-_ ]?me|example|placeholder|your[-_ ]|<[^>]+>|\$\{[^}]+\})$"
)
_TEST_SECRET_FIXTURE_VALUES = frozenset({"config"})
_URL_QUOTING_CHARSET = frozenset("%!*'();:@&=+$,/?#[]")


def _call_name(node: ast.Call) -> str:
    return _name(node.func)


def _security_aliases(nodes: list[ast.AST]) -> dict[str, str]:
    """Resolve common import aliases before applying security rules."""
    aliases: dict[str, str] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.asname:
                    aliases[item.asname] = item.name
                else:
                    name = item.name.split(".")[0]
                    aliases[name] = name
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                if item.name == "*":
                    continue
                module = node.module or item.name
                aliases[item.asname or item.name] = (
                    f"{module}.{item.name}" if node.module else item.name
                )
    return aliases


def _module_security_aliases(tree: ast.Module) -> dict[str, str]:
    """Resolve only imports in module scope for test-oracle attribution."""
    return _security_aliases(
        [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    )


def _scope_body(node: ast.AST) -> list[ast.stmt] | None:
    if isinstance(node, ast.Module):
        return node.body
    if isinstance(node, _FUNCTION_NODES):
        return node.body
    return None


def _scope_parameters(node: ast.AST) -> set[str]:
    if not isinstance(node, _FUNCTION_NODES):
        return set()
    arguments = node.args
    names = {
        argument.arg
        for argument in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        )
    }
    for argument in (arguments.vararg, arguments.kwarg):
        if argument:
            names.add(argument.arg)
    return names


def _binding_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return node.id
    if isinstance(node, ast.arg):
        return node.arg
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
        return node.name
    if isinstance(node, ast.MatchMapping):
        return node.rest
    return None


def _bound_names(statement: ast.AST) -> set[str]:
    if isinstance(statement, (*_FUNCTION_NODES, ast.ClassDef, ast.Lambda)):
        return {statement.name} if hasattr(statement, "name") else set()
    if (cached := getattr(statement, "_scan_bound_names", None)) is not None:
        return set(cached)
    comprehension_targets = {
        id(target)
        for child in _iter_ast_nodes(statement)
        if isinstance(
            child, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        )
        for generator in child.generators
        for target in _iter_ast_nodes(generator.target)
        if isinstance(target, ast.Name)
    }
    names: set[str] = set()
    pending = [statement]
    while pending:
        child = pending.pop()
        if isinstance(child, (*_FUNCTION_NODES, ast.ClassDef, ast.Lambda)):
            continue
        pending.extend(ast.iter_child_nodes(child))
        if isinstance(child, (ast.Import, ast.ImportFrom)):
            if any(item.name == "*" for item in child.names):
                names.add("*")
            names.update(
                item.asname
                or (
                    item.name.split(".")[0]
                    if isinstance(child, ast.Import)
                    else item.name
                )
                for item in child.names
                if item.name != "*"
            )
            continue
        if id(child) in comprehension_targets:
            continue
        name = _binding_name(child)
        if name:
            names.add(name)
    if hasattr(statement, "_scan_bound_names"):
        statement._scan_bound_names = frozenset(names)
    return names


def _normalized_call_name(node: ast.Call, aliases: dict[str, str]) -> str:
    name = _call_name(node)
    if not name:
        return name
    head, *tail = name.split(".")
    return ".".join([aliases.get(head, head), *tail])


def _scope_security_aliases(aliases: dict[str, str], node: ast.AST) -> dict[str, str]:
    """Resolve import aliases in source order within one lexical scope."""
    resolved = dict(aliases)
    body = _scope_body(node)
    if body is None:
        return resolved
    for name in _scope_parameters(node):
        resolved.pop(name, None)

    for statement in body:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            if any(item.name == "*" for item in statement.names):
                resolved.clear()
                continue
            imported = _security_aliases([statement])
            for name in _bound_names(statement):
                resolved.pop(name, None)
                if name in imported:
                    resolved[name] = imported[name]
            continue
        # Bindings in branches, exception handlers, and pattern matches are
        # conservatively invalidated; only unconditional direct imports restore
        # a recognized alias later in the scope.
        bound = _bound_names(statement)
        if "*" in bound:
            resolved.clear()
            continue
        for name in bound:
            resolved.pop(name, None)
    return resolved


def _test_oracle_body_nodes(node: ast.AST, aliases: dict[str, str]) -> list[ast.AST]:
    """Return test-body nodes without calls shadowed by comprehension targets."""
    layout = getattr(node, "_oracle_layout", None)
    if layout is None:
        nodes = [child for statement in node.body for child in _body_nodes(statement)]
        parents = _oracle_ancestor_map(node.body, node)
        if hasattr(node, "_oracle_layout"):
            node._oracle_layout = (nodes, parents)
    else:
        nodes, parents = layout
    for child in nodes:
        ancestors = parents.get(id(child), ())
        child._oracle_ancestors = ancestors
        child._oracle_parent = ancestors[-1][0] if ancestors else None
        child._oracle_scope = node
    shadowed_calls: set[int] = set()
    for child in nodes:
        if not isinstance(
            child, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            continue
        targets = {
            target.id
            for generator in child.generators
            for target in _iter_ast_nodes(generator.target)
            if isinstance(target, ast.Name)
            and isinstance(target.ctx, (ast.Store, ast.Del))
        }.intersection(aliases)
        if not targets:
            continue
        shadowed_calls.update(
            id(call)
            for call in _iter_ast_nodes(child)
            if isinstance(call, ast.Call)
            and _call_name(call).split(".", 1)[0] in targets
        )
    return [
        child
        for child in nodes
        if not isinstance(child, ast.Call) or id(child) not in shadowed_calls
    ]


def _oracle_ancestor_map(
    body: list[ast.stmt], scope: ast.AST | None = None
) -> dict[int, tuple]:
    parents = {}
    for statement in body:
        ancestors = ((scope, statement),) if scope is not None else ()
        parents[id(statement)] = ancestors
        pending = [(statement, ancestors)]
        while pending:
            parent, ancestors = pending.pop()
            for child in ast.iter_child_nodes(parent):
                parents[id(child)] = (*ancestors, (parent, child))
                pending.append((child, parents[id(child)]))
    return parents


def _resolved_ast_name(node: ast.AST | None, aliases: dict[str, str]) -> str:
    name = _name(node) if node is not None else ""
    head, *tail = name.split(".")
    return ".".join([aliases.get(head, head), *tail])


def _catches_assertion_error(
    handler: ast.ExceptHandler, aliases: dict[str, str]
) -> bool:
    if handler.type is None or _exception_type_catches_assertion(
        handler.type, handler, aliases
    ):
        return not (_handler_reraises(handler))
    return False


def _exception_type_catches_assertion(
    exception_type: ast.AST, handler: ast.ExceptHandler, aliases: dict[str, str]
) -> bool:
    if isinstance(exception_type, ast.Tuple):
        return any(
            _exception_type_catches_assertion(item, handler, aliases)
            for item in exception_type.elts
        )
    name = _resolved_ast_name(exception_type, aliases)
    return name in {
        "AssertionError",
        "builtins.AssertionError",
        "Exception",
        "builtins.Exception",
        "BaseException",
        "builtins.BaseException",
    }


def _handler_reraises(handler: ast.ExceptHandler) -> bool:
    if any(
        isinstance(child, ast.Return)
        for stmt in handler.body
        for child in _body_nodes(stmt)
    ):
        return False
    if not handler.body or not isinstance(handler.body[-1], ast.Raise):
        return False
    raised = handler.body[-1].exc
    return raised is None or (
        isinstance(raised, ast.Name) and raised.id == handler.name
    )


def _catches_oracle_failure(
    handler: ast.ExceptHandler, node: ast.AST, aliases: dict
) -> bool:
    if (
        not isinstance(node, ast.Call)
        or _normalized_call_name(node, aliases) != "pytest.fail"
    ):
        return _catches_assertion_error(handler, aliases)
    if _handler_reraises(handler):
        return False
    return handler.type is None or _catches_pytest_failure(handler.type, aliases)


def _catches_pytest_failure(exception: ast.AST, aliases: dict) -> bool:
    if isinstance(exception, ast.Tuple):
        return any(_catches_pytest_failure(item, aliases) for item in exception.elts)
    return _resolved_ast_name(exception, aliases) in {
        "BaseException",
        "builtins.BaseException",
        "pytest.fail.Exception",
        "_pytest.outcomes.Failed",
    }


def _effective_assertion(node: ast.AST, aliases: dict[str, str]) -> bool:
    """Assertions in a try suite count only when AssertionError is not swallowed."""
    ancestors = getattr(node, "_oracle_ancestors", ())
    for parent, child in ancestors:
        if _preceded_by_termination(parent, child):
            return False
        if _unreachable_constant_branch(parent, child):
            return False
        try_nodes = (ast.Try, getattr(ast, "TryStar", ast.Try))
        if isinstance(parent, try_nodes) and child in parent.body:
            if any(
                _catches_oracle_failure(handler, node, aliases)
                for handler in parent.handlers
            ):
                return False
            if any(_finally_suppresses_exception(stmt) for stmt in parent.finalbody):
                return False
        if isinstance(parent, ast.With) and child in parent.body:
            if any(
                _suppresses_assertion(item.context_expr, aliases, node)
                for item in parent.items
            ):
                return False
    return True


def _unreachable_constant_branch(parent: ast.AST, child: ast.AST) -> bool:
    if isinstance(parent, (ast.If, ast.IfExp)) and isinstance(
        parent.test, ast.Constant
    ):
        branch = {False: parent.body, True: parent.orelse}.get(parent.test.value, ())
        return child is branch if isinstance(parent, ast.IfExp) else child in branch
    if isinstance(parent, (ast.For, ast.While)) and child in parent.body:
        expression = parent.iter if isinstance(parent, ast.For) else parent.test
        value = _constant_value(expression)
        if isinstance(parent, ast.While):
            return value is not _UNKNOWN_CONSTANT and not bool(value)
        return isinstance(value, (str, bytes, tuple, list, dict, set)) and not value
    return _constant_short_circuit(parent, child)


def _constant_short_circuit(parent: ast.AST, child: ast.AST) -> bool:
    if isinstance(parent, ast.BoolOp) and child in parent.values:
        index = parent.values.index(child)
        for preceding in parent.values[:index]:
            if not isinstance(preceding, ast.Constant):
                continue
            if bool(preceding.value) == isinstance(parent.op, ast.Or):
                return True
    return False


def _preceded_by_termination(parent: ast.AST, child: ast.AST) -> bool:
    """Reject an assertion that follows an unconditional terminal statement."""
    for attribute in ("body", "orelse", "finalbody"):
        body = getattr(parent, attribute, None)
        if not isinstance(body, list) or child not in body:
            continue
        index = body.index(child)
        return any(
            isinstance(item, (ast.Return, ast.Raise, ast.Break, ast.Continue))
            for item in body[:index]
        )
    for handler in getattr(parent, "handlers", ()):
        if child not in handler.body:
            continue
        index = handler.body.index(child)
        return any(
            isinstance(item, (ast.Return, ast.Raise, ast.Break, ast.Continue))
            for item in handler.body[:index]
        )
    return False


def _finally_suppresses_exception(node: ast.AST) -> bool:
    return any(
        isinstance(child, (ast.Return, ast.Break, ast.Continue))
        for child in _body_nodes(node)
    )


def _suppresses_assertion(
    node: ast.AST, aliases: dict[str, str], oracle: ast.AST | None = None
) -> bool:
    if (
        isinstance(oracle, ast.Call)
        and _normalized_call_name(oracle, aliases) == "pytest.fail"
    ):
        return (
            isinstance(node, ast.Call)
            and _resolved_ast_name(node.func, aliases) == "contextlib.suppress"
            and any(
                _catches_pytest_failure(argument, aliases) for argument in node.args
            )
        )
    return (
        isinstance(node, ast.Call)
        and _resolved_ast_name(node.func, aliases) == "contextlib.suppress"
        and any(
            _resolved_ast_name(argument, aliases)
            in {
                "AssertionError",
                "builtins.AssertionError",
                "Exception",
                "builtins.Exception",
                "BaseException",
                "builtins.BaseException",
            }
            for argument in node.args
        )
    )


def _assertion_nodes(node: ast.AST, aliases: dict[str, str]) -> list[ast.AST]:
    """Collect explicit assertions, raises, and effective warnings-as-errors checks."""
    from .context_efficiency import _expected_exception_else_failure

    nodes = _test_oracle_body_nodes(node, aliases)
    return [
        child
        for child in nodes
        if isinstance(child, ast.Assert)
        and _effective_assertion(child, aliases)
        or isinstance(child, ast.Raise)
        and _effective_assertion(child, aliases)
        and isinstance(child.exc, (ast.Call, ast.Name))
        and (
            _name(child.exc.func if isinstance(child.exc, ast.Call) else child.exc)
            in {"AssertionError", "builtins.AssertionError"}
            or _expected_exception_else_failure(child, aliases)
        )
        or _warnings_as_errors(child, aliases)
    ]


def _warnings_as_errors(node: ast.AST, aliases: dict[str, str]) -> bool:
    if not isinstance(node, ast.With) or not _effective_warning_context(node, aliases):
        return False
    if not any(
        isinstance(item.context_expr, ast.Call)
        and _normalized_call_name(item.context_expr, aliases)
        == "warnings.catch_warnings"
        for item in node.items
    ):
        return False
    mode = None
    swallowed_warning = False
    for statement in node.body:
        if (
            mode == "error"
            and not swallowed_warning
            and isinstance(statement, ast.ClassDef)
            and (statement.bases or statement.keywords or statement.decorator_list)
            and _effective_assertion(statement, aliases)
        ):
            # Class construction executes bases, the class suite and metaclass.
            return True
        if _try_swallows_warning(statement, aliases):
            swallowed_warning = True
            continue
        calls = (
            [statement.value]
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
            else []
        )
        for call in calls:
            is_filter, filter_mode = _warning_filter_mode(call, aliases)
            if is_filter:
                mode = filter_mode
                continue
            if _normalized_call_name(call, aliases) == "warnings.resetwarnings":
                mode = None
                swallowed_warning = False
                continue
            if mode == "error" and (
                not swallowed_warning
                or _normalized_call_name(call, aliases) == "warnings.warn"
            ):
                return True
    return False


def _effective_warning_context(node: ast.AST, aliases: dict[str, str]) -> bool:
    if not _effective_assertion(node, aliases):
        return False
    try_nodes = (ast.Try, getattr(ast, "TryStar", ast.Try))
    for parent, child in getattr(node, "_oracle_ancestors", ()):
        if isinstance(parent, try_nodes) and child in parent.body:
            if any(
                _handler_catches_warning(handler, aliases)
                and not _handler_reraises(handler)
                for handler in parent.handlers
            ):
                return False
    return True


def _handler_catches_warning(
    handler: ast.ExceptHandler, aliases: dict[str, str]
) -> bool:
    if handler.type is None:
        return True
    types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(
        _resolved_ast_name(item, aliases)
        in {
            "Warning",
            "UserWarning",
            "builtins.Warning",
            "builtins.UserWarning",
            "Exception",
            "builtins.Exception",
            "BaseException",
            "builtins.BaseException",
        }
        for item in types
    )


def _try_swallows_warning(node: ast.AST, aliases: dict[str, str]) -> bool:
    """Detect a warning call caught and discarded inside a nested try block."""
    try_nodes = (ast.Try, getattr(ast, "TryStar", ast.Try))
    if not isinstance(node, try_nodes):
        return False
    if not any(
        isinstance(child, ast.Call)
        and _normalized_call_name(child, aliases) == "warnings.warn"
        for child in _body_nodes(node)
    ):
        return False
    return any(
        _handler_catches_warning(handler, aliases) and not _handler_reraises(handler)
        for handler in node.handlers
    )


def _warning_filter_mode(
    call: ast.Call, aliases: dict[str, str]
) -> tuple[bool, str | None]:
    if _normalized_call_name(call, aliases) != "warnings.simplefilter":
        return False, None
    if call.args and isinstance(call.args[0], ast.Constant):
        return True, call.args[0].value
    return True, None


def _security_finding(
    code: str, path: str, node: ast.AST, message: str, severity: str, **facts: Any
) -> dict[str, Any]:
    return {
        "code": code,
        "severity": severity,
        "path": path,
        "line": int(getattr(node, "lineno", 0)),
        "column": int(getattr(node, "col_offset", 0)),
        "message": message,
        "facts": facts,
    }


def _dynamic_execution_finding(
    call: str, relative: str, node: ast.AST
) -> dict[str, Any] | None:
    if call not in {"eval", "exec", "builtins.eval", "builtins.exec"}:
        return None
    if fixed := integrity.fixed_program_witness(relative, node, call):
        return _security_finding(
            "SECURITY_DYNAMIC_EXECUTION",
            relative,
            node,
            "Closed program input; runtime assurance remains incomplete."
            if fixed.get("disposition") != "PROVEN_FIXED_LITERAL_PROGRAM"
            else "Fixed literal-only program; the execution primitive is retained as an observation, not a demonstrated defect.",
            "INFO",
            call=call,
            **fixed,
        )
    rejected = contracts.literal_exec_rejected(node)
    return _security_finding(
        "SECURITY_DYNAMIC_EXECUTION",
        relative,
        node,
        "Literal source is rejected by Python syntax compilation; builtin execution primitive remains present."
        if rejected
        else "Dynamic code execution is reachable from source.",
        "INFO" if rejected else "HIGH",
        call=call,
        **rejected,
    )


def _security_call_finding(
    call: str, relative: str, node: ast.Call
) -> dict[str, Any] | None:
    """Dispatch primitive rules once, preserving their specific configuration gates."""
    from .review_integrity import shell_execution_enabled

    if call in {"eval", "exec", "builtins.eval", "builtins.exec"}:
        return _dynamic_execution_finding(call, relative, node)
    if call == "os.system":
        code = "SECURITY_OS_COMMAND"
        message = "os.system invokes a shell and should be replaced with an argv-based process boundary."
        facts = {}
    elif call in {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
    }:
        if not shell_execution_enabled(node):
            return None
        code = "SECURITY_SHELL_COMMAND"
        message = "subprocess shell execution is enabled; shell metacharacters can cross the command boundary."
        facts = {"call": call}
    elif call in {
        "pickle.load",
        "pickle.loads",
        "_pickle.load",
        "_pickle.loads",
        "dill.load",
        "dill.loads",
    }:
        code = "SECURITY_UNSAFE_DESERIALIZATION"
        message = "Pickle-like deserialization can execute attacker-controlled code."
        facts = {"call": call}
    elif call in {"yaml.load", "yaml.unsafe_load", "yaml.full_load"}:
        loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), None)
        loader_name = _name(loader) if isinstance(loader, ast.AST) else ""
        if (
            call == "yaml.load"
            and loader is not None
            and not loader_name.endswith(("UnsafeLoader", "FullLoader"))
        ):
            return None
        code = "SECURITY_UNSAFE_YAML"
        message = "YAML is loaded without an explicit reviewed Loader."
        facts = {"call": call}
    else:
        from .security_configuration import tls_finding

        return tls_finding(
            call, relative, node, getattr(node, "_security_configuration_aliases", {})
        )
    return _security_finding(code, relative, node, message, "HIGH", **facts)


def _bare_except_finding(
    relative: str, node: ast.ExceptHandler
) -> dict[str, Any] | None:
    if node.type is not None:
        return None
    return _security_finding(
        "QUALITY_BARE_EXCEPT",
        relative,
        node,
        "Bare except hides every failure type and weakens deterministic recovery.",
        "MEDIUM",
    )


def _secret_literal(node: ast.Assign | ast.AnnAssign) -> str | None:
    value = node.value
    if (
        not isinstance(value, ast.Constant)
        or not isinstance(value.value, str)
        or not value.value.strip()
        or _PLACEHOLDER_SECRET.match(value.value.strip())
    ):
        return None
    return value.value


def _url_quoting_charset(value: str) -> bool:
    """Recognize only the complete reserved-punctuation alphabet fixture."""
    visible = value.strip()
    return len(visible) == len(_URL_QUOTING_CHARSET) and set(visible) == set(
        _URL_QUOTING_CHARSET
    )


def _credential_role_witness(node, target, aliases):
    """Describe a symbolic declaration; it is not a non-credential exemption."""
    scope = getattr(node, "_security_lexical_scope", None)
    if not isinstance(scope, ast.ClassDef) or scope.decorator_list or scope.keywords:
        return {}
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    if len(targets) != 1 or not isinstance(target, ast.Name):
        return {}
    if not isinstance(node.value, ast.Constant) or node.value.value != target.id:
        return {}
    if integrity._builtin_repr_names_shadowed(node, {"str"}):
        return {}
    from .security_configuration import _relative_binding

    bindings = integrity._security_scope_request_aliases(
        getattr(scope, "_security_parent_scope", None), aliases, scope
    )
    bases = []
    for base in scope.bases:
        name = _name(base)
        head, separator, tail = name.partition(".")
        if _relative_binding(node, head) or (head != "str" and head not in bindings):
            return {}
        bases.append(bindings.get(head, head) + (separator + tail if separator else ""))
    if bases != ["str", "enum.Enum"]:
        return {}
    return {
        "role_candidate": "symbolic_enum_identifier",
        "role_evidence_scope": "source_declaration_only",
        "declaration_class": scope.name,
        "declaration_line": scope.lineno,
        "credential_use": "UNVERIFIED",
        "missing_evidence": ["complete_import_reexport_and_consumer_closure"],
    }


def _literal_assignment_diagnostic(
    relative: str, node: ast.Assign | ast.AnnAssign, target: ast.expr, aliases=None
) -> dict[str, Any] | None:
    if not isinstance(target, ast.Name) or not _SECRET_ASSIGNMENT.search(target.id):
        return None
    return _security_finding(
        "SECURITY_HARDCODED_SECRET",
        relative,
        node,
        "Credential-like material is assigned as a source literal.",
        "CRITICAL",
        name=target.id,
        **_credential_role_witness(node, target, aliases or {}),
    )


def _literal_assignment_diagnostics(
    relative: str, node: ast.Assign | ast.AnnAssign, aliases=None
) -> list[dict[str, Any]]:
    value = _secret_literal(node)
    is_test_source = "tests" in Path(relative).parts or Path(relative).name.startswith(
        "test_"
    )
    if value is None or (is_test_source and _url_quoting_charset(value)):
        return []
    # Evaluate the exception at the input boundary; diagnostic builders receive
    # only symbol/location metadata, never the credential literal itself.
    if (
        relative.startswith("tests/")
        and value.strip().casefold() in _TEST_SECRET_FIXTURE_VALUES
    ):
        return []
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    findings = []
    for target in targets:
        finding = _literal_assignment_diagnostic(relative, node, target, aliases)
        if finding is not None:
            findings.append(finding)
    return findings


def _security_source_files(root: Path) -> list[Path]:
    ignored = {
        ".git",
        ".factory",
        ".venv",
        "venv",
        "build",
        "dist",
        "tmp",
        "vendor",
        "site-packages",
        "__pycache__",
        "node_modules",
    }
    # Prune ignored descendants, never workspace parents: absolute /tmp roots
    # previously caused false CLEAN scans with zero inspected files.
    files = []
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in ignored]
        for name in names:
            path = Path(directory) / name
            if Path(name).match("*.py") and (path.is_file() or path.is_symlink()):
                files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


_UNKNOWN_CONSTANT = object()


def _boolean_operation_value(node: ast.BoolOp, known: dict[str, Any]) -> Any:
    if isinstance(node.op, ast.Or):
        for expression in node.values:
            value = _constant_value(expression, known)
            if value is _UNKNOWN_CONSTANT:
                return _UNKNOWN_CONSTANT
            if bool(value):
                return value
        return value
    for expression in node.values:
        value = _constant_value(expression, known)
        if value is _UNKNOWN_CONSTANT:
            return _UNKNOWN_CONSTANT
        if not bool(value):
            return value
    return value


def _comparison_value(node: ast.Compare, known: dict[str, Any]) -> Any:
    if len(node.ops) != 1:
        return _UNKNOWN_CONSTANT
    left = _constant_value(node.left, known)
    right = _constant_value(node.comparators[0], known)
    if left is _UNKNOWN_CONSTANT or right is _UNKNOWN_CONSTANT:
        return _UNKNOWN_CONSTANT
    operations = {
        ast.Eq: operator.eq,
        ast.NotEq: operator.ne,
        ast.Is: operator.is_,
        ast.IsNot: operator.is_not,
        ast.Lt: operator.lt,
        ast.LtE: operator.le,
        ast.Gt: operator.gt,
        ast.GtE: operator.ge,
        ast.In: lambda value, container: operator.contains(container, value),
        ast.NotIn: lambda value, container: not operator.contains(container, value),
    }
    function = operations.get(type(node.ops[0]))
    if function is None:
        return _UNKNOWN_CONSTANT
    try:
        return function(left, right)
    except (TypeError, ValueError):
        return _UNKNOWN_CONSTANT


def _constant_truth_value(node: ast.expr, known: dict[str, Any]) -> bool | None:
    value = _constant_value(node, known)
    if value is not _UNKNOWN_CONSTANT:
        return bool(value)
    if isinstance(node, ast.BoolOp):
        values = [_constant_truth_value(child, known) for child in node.values]
        if isinstance(node.op, ast.Or):
            if True in values:
                return True
            return False if all(value is False for value in values) else None
        if False in values:
            return False
        return True if all(value is True for value in values) else None
    return None


def _constant_value(node: ast.expr, known: dict[str, Any] | None = None) -> Any:
    known = known or {}
    if isinstance(node, ast.Name):
        return known.get(node.id, _UNKNOWN_CONSTANT)
    if isinstance(node, ast.BinOp):
        return _constant_binary_value(node, known)
    if isinstance(node, ast.BoolOp):
        return _boolean_operation_value(node, known)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        truth = _constant_truth_value(node.operand, known)
        return _UNKNOWN_CONSTANT if truth is None else not truth
    if isinstance(node, ast.Compare):
        return _comparison_value(node, known)
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, RecursionError):
        return _UNKNOWN_CONSTANT


def _constant_binary_value(node: ast.BinOp, known: dict[str, Any]) -> Any:
    """Fold small numeric expressions without evaluating arbitrary Python."""
    left = _constant_value(node.left, known)
    right = _constant_value(node.right, known)
    if (
        left is _UNKNOWN_CONSTANT
        or right is _UNKNOWN_CONSTANT
        or type(left) not in {int, float}
        or type(right) not in {int, float}
        or abs(left) > 1_000_000_000_000
        or abs(right) > 1_000_000_000_000
    ):
        return _UNKNOWN_CONSTANT
    operations = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.Pow: operator.pow,
    }
    function = operations.get(type(node.op))
    if function is None or (isinstance(node.op, ast.Pow) and abs(right) > 12):
        return _UNKNOWN_CONSTANT
    try:
        value = function(left, right)
    except (ArithmeticError, OverflowError, TypeError, ValueError):
        return _UNKNOWN_CONSTANT
    if type(value) not in {int, float} or abs(value) > 1_000_000_000_000:
        return _UNKNOWN_CONSTANT
    return value


def _direct_test_vacuous_assertions(node: ast.AST, aliases=None) -> set[int]:
    from .review_integrity import _direct_vacuous_assertions

    return _direct_vacuous_assertions(
        node, aliases or {}, _vacuous_assertion, _remember_direct_constant_assignment
    )


def _remember_direct_constant_assignment(statement, known):
    from .review_integrity import remember_direct_constant_assignment

    remember_direct_constant_assignment(statement, known)


def _vacuous_assertion(node: ast.expr, known: dict[str, Any] | None = None) -> bool:
    if isinstance(node, ast.Tuple) and any(
        not isinstance(item, ast.Starred) for item in node.elts
    ):
        return True
    truth = _constant_truth_value(node, known or {})
    if truth is not None:
        return truth
    if not isinstance(node, ast.Compare) or len(node.ops) != 1:
        return False
    if (
        isinstance(node.ops[0], ast.GtE)
        and isinstance(node.left, ast.Call)
        and _name(node.left.func) == "len"
        and len(node.left.args) == 1
        and not node.left.keywords
        and isinstance(node.comparators[0], ast.Constant)
        and node.comparators[0].value == 0
    ):
        return True
    if not isinstance(node.ops[0], (ast.Eq, ast.Is, ast.LtE, ast.GtE)):
        return False
    operands = [node.left, *node.comparators]
    # Calls, descriptors and indexed reads can return different values each time.
    if any(
        isinstance(n, (ast.Call, ast.Await, ast.Attribute, ast.Subscript))
        for x in operands
        for n in ast.walk(x)
    ):
        return False
    return ast.dump(operands[0]) == ast.dump(operands[1])


_UNITTEST_ASSERTIONS = {
    "assertAlmostEqual",
    "assertCountEqual",
    "assertDictEqual",
    "assertEqual",
    "assertFalse",
    "assertGreater",
    "assertGreaterEqual",
    "assertIn",
    "assertIs",
    "assertIsInstance",
    "assertIsNotNone",
    "assertIsNone",
    "assertLess",
    "assertLessEqual",
    "assertListEqual",
    "assertLogs",
    "assertNoLogs",
    "assertNotAlmostEqual",
    "assertNotEqual",
    "assertNotIn",
    "assertNotIsInstance",
    "assertNotIsNone",
    "assertNotRegex",
    "assertRaises",
    "assertRaisesRegex",
    "assertRegex",
    "assertSetEqual",
    "assertSequenceEqual",
    "assertTrue",
    "assertTupleEqual",
    "assertWarns",
    "assertWarnsRegex",
}
_ORACLE_HELPER_PREFIXES = (
    "assert",
    "check",
    "ensure",
    "expect",
    "require",
    "validate",
    "verify",
)


def _is_oracle_helper_name(name: str) -> bool:
    return name.lower().startswith(_ORACLE_HELPER_PREFIXES) or name.lower().startswith(
        "test_"
    )


def _assertion_call(
    node: ast.AST,
    aliases: dict[str, str],
    helper_names: set[str] | None = None,
    *,
    unittest_context: bool = False,
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    name = _normalized_call_name(node, aliases)
    leaf = name.rsplit(".", 1)[-1]
    return (
        name in {"pytest.raises", "pytest.warns"}
        or (name == "pytest.fail" and _call_name(node).split(".", 1)[0] in aliases)
        or _mock_argument_oracle(node, aliases)
        or _click_callback_oracle(node, aliases, helper_names) is not None
        or (
            unittest_context
            and leaf in _UNITTEST_ASSERTIONS
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in {"self", "cls"}
        )
        or (
            name in (helper_names or set())
            and (
                name not in {"typing.assert_type", "typing_extensions.assert_type"}
                or _call_name(node).split(".", 1)[0] in aliases
            )
        )
    )


def _ty_assertion_helpers(node: ast.AST, aliases: dict[str, str]) -> set[str]:
    """Recognize direct, unsuppressed calls to the canonical two-argument API."""
    module = getattr(node, "_oracle_module", None)
    lines = getattr(module, "_oracle_source_lines", ())
    if contracts._ty_assertion_provider_mutated(module, aliases):
        return set()
    helpers = set()
    for call in _test_oracle_body_nodes(node, aliases):
        if not isinstance(call, ast.Call) or len(call.args) != 2 or call.keywords:
            continue
        if any(isinstance(arg, ast.Starred) for arg in call.args):
            continue
        name = _normalized_call_name(call, aliases)
        if name not in {"typing.assert_type", "typing_extensions.assert_type"}:
            continue
        head = _call_name(call).split(".", 1)[0]
        if head not in aliases or call.lineno > len(lines):
            continue
        comments = "\n".join(
            line.partition("#")[2] for line in lines[call.lineno - 1 : call.end_lineno]
        )
        if re.search(r"\bty:\s*ignore\b", comments):
            continue
        helpers.add(name)
    return helpers


def _mock_argument_oracle(node: ast.AST, aliases: dict, *, uncalled=False) -> bool:
    methods = {
        "assert_called_with",
        "assert_called_once_with",
        "assert_called",
        "assert_called_once",
        "assert_any_call",
        "assert_has_calls",
        "assert_not_called",
        "assert_awaited_with",
        "assert_awaited_once_with",
        "assert_any_await",
        "assert_has_awaits",
        "assert_not_awaited",
        "assert_awaited",
        "assert_awaited_once",
    }
    if uncalled:
        return (
            isinstance(node, ast.Attribute)
            and node.attr in methods
            and (_mock_receiver_has_provenance(node, aliases))
        )
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in methods:
        return False
    if not _mock_receiver_has_provenance(node, aliases):
        return False
    if node.func.attr in {
        "assert_not_called",
        "assert_not_awaited",
        "assert_called",
        "assert_called_once",
        "assert_awaited",
        "assert_awaited_once",
    } and not _injected_mock_use(node, aliases):
        return False
    return not _mock_self_check(node)


_UNITTEST_MOCK_CONSTRUCTORS = {
    "unittest.mock.AsyncMock",
    "unittest.mock.MagicMock",
    "unittest.mock.Mock",
    "unittest.mock.NonCallableMagicMock",
    "unittest.mock.NonCallableMock",
    "unittest.mock.PropertyMock",
    "unittest.mock.create_autospec",
    "unittest.mock.mock_open",
}


def _mock_receiver_has_provenance(assertion, aliases):
    """Trust mock assertions only for locally constructed unittest.mock values."""
    scope = getattr(assertion, "_oracle_scope", None)
    receiver = _mock_root_name(
        getattr(assertion, "func", assertion).value, scope, aliases
    )
    if receiver is None or scope is None:
        return False
    scoped_aliases = _scope_security_aliases(aliases, scope)
    nodes = _test_oracle_body_nodes(scope, scoped_aliases)
    from .intent_quality import _mock_scope_binding

    proven = _mock_scope_binding(nodes, receiver, assertion, scoped_aliases)
    module = getattr(scope, "_oracle_module", None)
    fixture_proven = bool(
        module is not None
        and _mock_fixture_binding(
            scope,
            receiver,
            module,
            _scope_security_aliases(_module_security_aliases(module), module),
        )
    )
    patch_proven = _mock_patch_parameter(scope, receiver, scoped_aliases)
    context_proven = _mock_context_patch_parameter(
        scope, receiver, assertion, scoped_aliases
    )
    from .review_integrity import mock_patch_dict_slot

    mapping_proven = mock_patch_dict_slot(
        getattr(assertion, "func", assertion).value,
        receiver,
        assertion,
        scoped_aliases,
        nodes,
        _UNITTEST_MOCK_CONSTRUCTORS,
        _normalized_call_name,
        _name_rebound,
        _effective_assertion,
        _mock_root_name,
    )
    if (
        not proven
        and not fixture_proven
        and not patch_proven
        and not context_proven
        and not mapping_proven
        and not (
            receiver in _scope_parameters(scope)
            or any(
                isinstance(node, ast.stmt)
                and node.lineno < assertion.lineno
                and receiver in _bound_names(node)
                for node in nodes
            )
            or _scope_binds_name(scope, receiver)
        )
    ):
        if module is not None:
            module_aliases = _scope_security_aliases(
                _module_security_aliases(module), module
            )
            proven = _mock_scope_binding(
                module.body, receiver, assertion, module_aliases
            )
    proven = (
        proven or fixture_proven or patch_proven or context_proven or mapping_proven
    )
    return proven and not _mock_root_was_mutated(scope, receiver, assertion, aliases)


def _scope_binds_name(scope, name):
    return any(name in _bound_names(statement) for statement in scope.body)


def _mock_fixture_binding(scope, name, module, aliases):
    if name not in _scope_parameters(scope) or _scope_binds_name(scope, name):
        return False
    from .mock_fixture_provenance import fixture_is_mock

    return fixture_is_mock(module, name)


def _module_has_rebinding(module, name, fixture):
    return any(
        statement is not fixture and name in _bound_names(statement)
        for statement in module.body
    )


def _mock_patch_parameter(scope, name, aliases):
    if (
        not isinstance(scope, _FUNCTION_NODES)
        or not scope.decorator_list
        or _scope_binds_name(scope, name)
        or any(not _default_mock_patch(item, aliases) for item in scope.decorator_list)
    ):
        return False
    parameters = [arg.arg for arg in [*scope.args.posonlyargs, *scope.args.args]]
    injected = len(scope.decorator_list)
    return name in parameters[:injected]


def _default_mock_patch(decorator, aliases):
    if not isinstance(decorator, ast.Call) or any(
        keyword.arg in {"new", "new_callable"} or keyword.arg is None
        for keyword in decorator.keywords
    ):
        return False
    name = _normalized_call_name(decorator, aliases)
    if name == "unittest.mock.patch.object":
        return len(decorator.args) == 2
    if name == "unittest.mock.patch":
        return len(decorator.args) == 1
    return False


def _mock_context_patch_parameter(scope, name, assertion, aliases):
    nodes = _test_oracle_body_nodes(scope, aliases)
    return isinstance(scope, _FUNCTION_NODES) and any(
        isinstance(node, ast.With)
        and _in_current_test_body(node)
        and any(parent is node for parent, _ in assertion._oracle_ancestors)
        and not any(
            isinstance(
                item,
                (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr, ast.Delete),
            )
            and (item.lineno, item.col_offset)
            < (assertion.lineno, assertion.col_offset)
            and name in _bound_names(item)
            for item in nodes
        )
        and any(
            isinstance(item.optional_vars, ast.Name)
            and item.optional_vars.id == name
            and isinstance(item.context_expr, ast.Call)
            and _default_mock_patch(item.context_expr, aliases)
            for item in node.items
        )
        for node in nodes
    )


def _mock_root_name(node, scope, aliases):
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) == 2
        and _mock_getattr_selector(node.args[1], scope)
        and not node.keywords
        and not aliases.get("getattr")
        and scope is not None
        and "getattr" not in _scope_parameters(scope)
        and not _scope_binds_name(scope, "getattr")
        and not _scope_binds_name(
            getattr(scope, "_oracle_module", ast.Module(body=[], type_ignores=[])),
            "getattr",
        )
    ):
        return _mock_root_name(node.args[0], scope, aliases)
    return node.id if isinstance(node, ast.Name) else None


def _mock_getattr_selector(selector, scope):
    if isinstance(selector, ast.Name):
        return selector.id not in {"__class__", "__dict__", "__getattribute__"}
    return (
        isinstance(selector, ast.Constant)
        and isinstance(selector.value, str)
        and not (selector.value.startswith("__") and selector.value.endswith("__"))
    )


def _mock_root_was_mutated(scope, root, before, aliases):
    from .review_integrity import _source_name_aliases

    nodes = _test_oracle_body_nodes(scope, {})
    origin = next(
        (
            node
            for node in nodes
            if isinstance(node, ast.Name)
            and node.id == root
            and isinstance(node.ctx, ast.Store)
            and _in_current_test_body(node)
            and (node.lineno, node.col_offset) < (before.lineno, before.col_offset)
        ),
        None,
    )
    for node in nodes:
        if (getattr(node, "lineno", 0), getattr(node, "col_offset", 0)) >= (
            before.lineno,
            before.col_offset,
        ):
            continue
        if (
            isinstance(node, (ast.Name, ast.Attribute, ast.Subscript))
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and (not isinstance(node, ast.Name) or node.id == root)
            and node is not origin
            and _mock_root_name(node, scope, aliases)
            in _source_name_aliases(scope, {root}, node)
        ):
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "configure_mock"
            and _mock_root_name(node.func.value, scope, aliases)
            in _source_name_aliases(scope, {root}, node)
        ):
            return True
        if (
            isinstance(node, ast.Call)
            and _call_name(node)
            in {
                "setattr",
                "delattr",
            }
            and node.args
            and _mock_root_name(node.args[0], scope, aliases)
            in _source_name_aliases(scope, {root}, node)
        ):
            return True
    return False


def _mock_constructor_binding(statement, name, aliases):
    targets = (
        statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    )
    return (
        any(isinstance(target, ast.Name) and target.id == name for target in targets)
        and _effective_assertion(statement, aliases)
        and isinstance(statement.value, ast.Call)
        and _normalized_call_name(statement.value, aliases)
        in _UNITTEST_MOCK_CONSTRUCTORS
    )


def _injected_mock_use(assertion: ast.Call, aliases: dict[str, str]) -> bool:
    """Track an injected mock through an imported dependency receiver call."""
    scope = getattr(assertion, "_oracle_scope", None)
    if scope is None:
        return False
    receiver = _name(assertion.func.value)
    scoped_aliases = _scope_security_aliases(aliases, scope)
    nodes = _test_oracle_body_nodes(scope, scoped_aliases)
    return _direct_mock_dependency_use(
        assertion, receiver, scoped_aliases, nodes
    ) or any(
        _injected_mock_assertion_proven(
            constructor, assertion, receiver, aliases, scoped_aliases, nodes
        )
        for constructor in nodes
    )


def _direct_mock_dependency_use(assertion, receiver, aliases, nodes):
    """Credit interaction checks after passing a mock to an executed dependency."""
    from .review_integrity import assigned_sync_function_call

    for call in nodes:
        if not isinstance(call, ast.Call) or call.lineno >= assertion.lineno:
            continue
        if not _in_current_test_body(call) or not _effective_assertion(call, aliases):
            continue
        name = _normalized_call_name(call, aliases)
        scope = getattr(assertion, "_oracle_scope", None)
        if _call_name(call) in getattr(
            scope, "_oracle_async_functions", set()
        ) and not isinstance(getattr(call, "_oracle_parent", None), ast.Await):
            continue
        if name == receiver or name.startswith(("unittest.mock.", "mock.")):
            continue
        parent = getattr(call, "_oracle_parent", None)
        if isinstance(parent, (ast.Assign, ast.AnnAssign)) and (
            scope is None
            or not assigned_sync_function_call(
                call, scope, getattr(scope, "_oracle_module", ast.Module())
            )
        ):
            continue
        arguments = [*call.args, *(item.value for item in call.keywords)]
        if any(
            isinstance(item, ast.Name) and item.id == receiver for item in arguments
        ):
            if not _name_rebound(nodes, receiver, call.lineno, assertion.lineno):
                return True
    return False


def _injected_mock_assertion_proven(
    constructor, assertion, receiver, aliases, scoped_aliases, nodes
):
    if not _effective_assertion(constructor, aliases):
        return False
    if not _injected_dependency_constructor(
        constructor, receiver, assertion, scoped_aliases
    ):
        return False
    targets = _assignment_names(constructor)
    injected_at = constructor.lineno
    if not targets or _name_rebound(nodes, receiver, injected_at, assertion.lineno):
        return False
    return any(
        _injected_receiver_call(call, targets, injected_at, assertion, aliases, nodes)
        for call in nodes
    )


def _injected_receiver_call(call, targets, injected_at, assertion, aliases, nodes):
    if not _receiver_method_call(call, targets, assertion, aliases):
        return False
    if not _effective_assertion(call, aliases):
        return False
    return not any(
        _name_rebound(nodes, target, injected_at, call.lineno) for target in targets
    )


def _injected_dependency_constructor(call, receiver, assertion, aliases):
    if not isinstance(call, ast.Call) or call.lineno >= assertion.lineno:
        return False
    if not _in_current_test_body(call):
        return False
    constructor = _normalized_call_name(call, aliases)
    if constructor.startswith(("unittest.mock.", "mock.")):
        return False
    imported = constructor != _call_name(call)
    receives_mock = any(
        isinstance(value, ast.Name) and value.id == receiver
        for value in [*call.args, *(keyword.value for keyword in call.keywords)]
    )
    return (
        imported
        and receives_mock
        and isinstance(getattr(call, "_oracle_parent", None), ast.Assign)
    )


def _assignment_names(call):
    parent = getattr(call, "_oracle_parent", None)
    if not isinstance(parent, ast.Assign) or len(parent.targets) != 1:
        return set()
    return {
        target.id
        for target in getattr(parent, "targets", ())
        if isinstance(target, ast.Name)
    }


def _receiver_method_call(call, targets, assertion, _aliases):
    return (
        isinstance(call, ast.Call)
        and call.lineno < assertion.lineno
        and _in_current_test_body(call)
        and isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in targets
        and call.func.attr not in {"assert", "assert_called", "assert_awaited"}
    )


def _in_current_test_body(node):
    scope = getattr(node, "_oracle_scope", None)
    return not any(
        parent is not scope
        and isinstance(
            parent,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        )
        for parent, _child in getattr(node, "_oracle_ancestors", ())
    )


def _name_rebound(nodes, name, after, before):
    return any(
        after < node.lineno < before and name in _bound_names(node)
        for node in nodes
        if isinstance(
            node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr, ast.Delete)
        )
    )


def _mock_self_check(node: ast.Call) -> bool:
    scope = getattr(node, "_oracle_scope", None)
    if scope is None:
        return False
    receiver = _name(node.func.value)
    return any(
        _call_name(child) == receiver
        for statement in scope.body
        for child in _body_nodes(statement)
        if isinstance(child, ast.Call)
        and (child.lineno, child.col_offset) < (node.lineno, node.col_offset)
    )


def _click_callback_oracle(
    call: ast.Call, aliases: dict[str, str], helpers: set[str] | None = None
) -> str | None:
    """Follow a local Click callback only through a proven non-catching runner."""
    scope = getattr(call, "_oracle_scope", None)
    if (
        scope is None
        or not isinstance(call.func, ast.Attribute)
        or call.func.attr != "invoke"
        or not isinstance(call.func.value, ast.Name)
        or not call.args
        or not isinstance(call.args[0], ast.Name)
        or not any(
            kw.arg == "catch_exceptions"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is False
            for kw in call.keywords
        )
        or any(kw.arg is None for kw in call.keywords)
    ):
        return None
    receiver, command = call.func.value.id, call.args[0].id
    if _click_receiver_mutated(scope, receiver):
        return None
    bindings = [stmt for stmt in scope.body if receiver in _bound_names(stmt)]
    fixture = receiver in _scope_parameters(scope) and receiver in getattr(
        scope, "_oracle_click_runners", ()
    )
    constructed = (
        len(bindings) == 1
        and isinstance(bindings[0], (ast.Assign, ast.AnnAssign))
        and isinstance(bindings[0].value, ast.Call)
        and _call_name(bindings[0].value).split(".", 1)[0] in aliases
        and _normalized_call_name(bindings[0].value, aliases)
        == "click.testing.CliRunner"
        and bindings[0].lineno < call.lineno
    )
    if not ((fixture and not bindings) or constructed):
        return None
    declarations = [stmt for stmt in scope.body if command in _bound_names(stmt)]
    if len(declarations) != 1 or not isinstance(declarations[0], ast.FunctionDef):
        return None
    callback = declarations[0]
    if callback.lineno >= call.lineno or not _propagating_click_decorators(
        callback, aliases
    ):
        return None
    scoped = _scope_security_aliases(aliases, callback)
    if not _meaningful_local_assertion(callback, scoped, helpers):
        return None
    return "strong" if _strong_local_assertion(callback, scoped, helpers) else "weak"


def _click_receiver_mutated(scope: ast.AST, receiver: str) -> bool:
    for statement in scope.body:
        for child in _body_nodes(statement):
            if (
                isinstance(child, (ast.Assign, ast.AnnAssign))
                and isinstance(child.value, ast.Name)
                and child.value.id == receiver
            ):
                return True
            if isinstance(child, ast.Attribute) and isinstance(
                child.ctx, (ast.Store, ast.Del)
            ):
                if _name(child).split(".", 1)[0] == receiver:
                    return True
            if isinstance(child, ast.Call) and any(
                isinstance(argument, ast.Name) and argument.id == receiver
                for argument in (
                    *child.args,
                    *(keyword.value for keyword in child.keywords),
                )
            ):
                return True
    return False


def _propagating_click_decorators(callback: ast.FunctionDef, aliases: dict) -> bool:
    names = [
        _resolved_ast_name(
            decorator.func if isinstance(decorator, ast.Call) else decorator, aliases
        )
        for decorator in callback.decorator_list
    ]
    return (
        bool(names)
        and names[0] == "click.command"
        and all(
            _name(
                decorator.func if isinstance(decorator, ast.Call) else decorator
            ).split(".", 1)[0]
            in aliases
            for decorator in callback.decorator_list
        )
        and all(
            name
            in {
                "click.command",
                "click.option",
                "click.argument",
                "click.pass_context",
                "click.pass_obj",
            }
            for name in names
        )
        and not any(
            isinstance(decorator, ast.Call)
            and any(kw.arg in {None, "cls"} for kw in decorator.keywords)
            for decorator in callback.decorator_list
        )
    )


def _click_runner_fixtures(tree: ast.Module, aliases: dict[str, str]) -> dict:
    fixtures = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or not any(
            _resolved_ast_name(
                decorator.func if isinstance(decorator, ast.Call) else decorator,
                aliases,
            )
            == "pytest.fixture"
            for decorator in node.decorator_list
        ):
            continue
        returns = [
            child
            for statement in node.body
            for child in _body_nodes(statement)
            if isinstance(child, (ast.Return, ast.Yield, ast.YieldFrom))
        ]
        fixtures[node.name] = (
            len(node.decorator_list) == 1
            and bool(returns)
            and not any(
                isinstance(decorator, ast.Call)
                and any(kw.arg in {None, "name"} for kw in decorator.keywords)
                for decorator in node.decorator_list
            )
            and all(
                isinstance(returned, ast.Return)
                and isinstance(returned.value, ast.Call)
                and _call_name(returned.value).split(".", 1)[0]
                in _scope_security_aliases(aliases, node)
                and _normalized_call_name(
                    returned.value, _scope_security_aliases(aliases, node)
                )
                == "click.testing.CliRunner"
                for returned in returns
            )
        )
    return fixtures


def _unittest_testcase_classes(
    tree: ast.Module, aliases: dict[str, str]
) -> tuple[dict[str, ast.ClassDef], dict[str, tuple[str, ...]], set[str]]:
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    # Importing unittest.mock binds unittest to the submodule in the generic
    # alias table; written unittest.TestCase still names the package's class.
    base_names = {
        name: tuple(
            _name(base)
            if _name(base).startswith("unittest.")
            else _resolved_ast_name(base, aliases)
            for base in node.bases
        )
        for name, node in classes.items()
    }

    def derives_from_testcase(name: str, seen: set[str] | None = None) -> bool:
        seen = set() if seen is None else seen
        if name in seen:
            return False
        seen.add(name)
        return any(
            base in {"unittest.TestCase", "unittest.case.TestCase"}
            or (base in classes and derives_from_testcase(base, seen))
            for base in base_names.get(name, ())
        )

    testcase_classes = {name for name in classes if derives_from_testcase(name)}
    return classes, base_names, testcase_classes


def _unittest_test_methods(tree: ast.Module, aliases: dict[str, str]) -> set[int]:
    classes, base_names, testcase_classes = _unittest_testcase_classes(tree, aliases)
    # Enumerate concrete TestCases and their local mixins through one closure.
    pending, seen, methods = list(testcase_classes), set(), set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        methods.update(
            id(method)
            for method in classes[name].body
            if isinstance(method, _FUNCTION_NODES)
        )
        pending.extend(base for base in base_names.get(name, ()) if base in classes)
    return methods


def _empty_test_parameters(node, aliases):
    from .security_configuration import _keyword

    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call) or any(
            isinstance(arg, ast.Starred) for arg in decorator.args
        ):
            continue
        if (
            _call_name(decorator).split(".")[0] not in aliases
            or _normalized_call_name(decorator, aliases) != "pytest.mark.parametrize"
        ):
            continue
        value = _constant_value(_keyword(decorator, "argvalues", 1))
        if isinstance(value, (str, bytes, list, tuple, dict, set)) and not value:
            return True
    return False


def _unconditionally_skipped_test(node: ast.AST) -> bool:
    if not isinstance(node, _FUNCTION_NODES):
        return False
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = _name(target)
        if name in {"skip", "pytest.mark.skip", "unittest.skip"} or name.endswith(
            ".mark.skip"
        ):
            return True
    return False


def _performance_benchmark_test(
    node: ast.AST, aliases: dict[str, str] | None = None
) -> bool:
    """Exclude only explicitly typed or marked benchmark bodies."""
    if not isinstance(node, _FUNCTION_NODES):
        return False
    if not node.name.startswith("test_"):
        return False
    benchmark_parameter = next(
        (
            argument
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            )
            if argument.arg == "benchmark"
        ),
        None,
    )
    if benchmark_parameter is None:
        return False
    resolved_aliases = aliases or {}
    typed_fixture = _resolved_ast_name(
        benchmark_parameter.annotation, resolved_aliases
    ) in {
        "pytest_benchmark.BenchmarkFixture",
        "pytest_benchmark.fixture.BenchmarkFixture",
        "pytest_codspeed.BenchmarkFixture",
    }
    marked_fixture = any(
        _resolved_ast_name(
            decorator.func if isinstance(decorator, ast.Call) else decorator,
            resolved_aliases,
        )
        == "pytest.mark.benchmark"
        for decorator in node.decorator_list
    )
    return (typed_fixture or marked_fixture) and _benchmark_fixture_used(node)


def _benchmark_fixture_used(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """A later rebinding does not erase an earlier genuine fixture use."""
    for statement in node.body:
        for child in _body_nodes(statement):
            if (
                isinstance(child, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
                and child.value is not None
                and any(
                    _benchmark_fixture_use(value) for value in _body_nodes(child.value)
                )
            ):
                return True
            if _benchmark_fixture_use(child):
                return True
            if _binding_name(child) == "benchmark" or (
                isinstance(child, (ast.Import, ast.ImportFrom))
                and "benchmark" in _bound_names(child)
            ):
                return False
    return False


def _benchmark_fixture_use(node: ast.AST) -> bool:
    """Match ``benchmark(...)`` calls and ``@benchmark`` on a nested function."""
    if isinstance(node, ast.Call):
        return _call_name(node).split(".", 1)[0] == "benchmark"
    return isinstance(node, _FUNCTION_NODES) and any(
        isinstance(decorator, ast.Name) and decorator.id == "benchmark"
        for decorator in node.decorator_list
    )


def _local_assertion_nodes(
    node: ast.AST,
    aliases: dict[str, str],
    helper_names: set[str] | None = None,
    *,
    unittest_context: bool = False,
    strong: bool = False,
    nodes: list[ast.AST] | None = None,
) -> list[ast.AST]:
    nodes = _test_oracle_body_nodes(node, aliases) if nodes is None else nodes
    vacuous = _direct_test_vacuous_assertions(
        node, _scope_security_aliases(aliases, node)
    )
    result = []
    for child in nodes:
        if not isinstance(child, (ast.Assert, ast.Call)) or not _effective_assertion(
            child, aliases
        ):
            continue
        if isinstance(child, ast.Assert):
            if id(child) in vacuous or _vacuous_assertion(child.test):
                continue
            expression = child.test
        elif _assertion_call(
            child, aliases, helper_names, unittest_context=unittest_context
        ):
            if unittest_context and _vacuous_unittest_call(child):
                continue
            expression = child
        else:
            continue
        if not strong or _weak_assertion_reason(expression, aliases) is None:
            result.append(child)
    return result


def _vacuous_unittest_call(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute) or _name(node.func.value) not in {
        "self",
        "cls",
    }:
        return False
    method = node.func.attr
    if method in {"assertTrue", "assertFalse"} and node.args:
        expression = node.args[0]
        if method == "assertFalse":
            expression = ast.UnaryOp(op=ast.Not(), operand=expression)
        return _vacuous_assertion(expression)
    if (
        method
        in {
            "assertEqual",
            "assertTupleEqual",
            "assertListEqual",
            "assertDictEqual",
            "assertSetEqual",
            "assertSequenceEqual",
        }
        and len(node.args) >= 2
    ):
        return _vacuous_assertion(
            ast.Compare(left=node.args[0], ops=[ast.Eq()], comparators=[node.args[1]])
        )
    return False


def _meaningful_local_assertion(
    node: ast.AST,
    aliases: dict[str, str],
    helper_names: set[str] | None = None,
    *,
    unittest_context: bool = False,
) -> bool:
    return bool(
        _local_assertion_nodes(
            node, aliases, helper_names, unittest_context=unittest_context
        )
    ) or _has_manual_failure(node, aliases)


def _strong_local_assertion(
    node: ast.AST,
    aliases: dict[str, str],
    helper_names: set[str] | None = None,
    *,
    unittest_context: bool = False,
) -> bool:
    """Return true only when a helper carries a non-weak oracle."""
    return bool(
        _local_assertion_nodes(
            node, aliases, helper_names, unittest_context=unittest_context, strong=True
        )
    ) or _has_manual_failure(node, aliases)


def _local_assertion_helpers(
    tree: ast.Module, aliases: dict[str, str], *, unittest_context: bool = False
) -> set[str]:
    functions = {
        node.name: node for node in tree.body if isinstance(node, _FUNCTION_NODES)
    }
    helpers: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, node in functions.items():
            if name not in helpers and _strong_local_assertion(
                node,
                _scope_security_aliases(aliases, node),
                helpers,
                unittest_context=unittest_context,
            ):
                helpers.add(name)
                changed = True
    return helpers


def _local_weak_assertion_helpers(
    tree: ast.Module,
    aliases: dict[str, str],
    *,
    unittest_context: bool = False,
    strong_helpers: set[str] | None = None,
) -> set[str]:
    functions = {
        node.name: node for node in tree.body if isinstance(node, _FUNCTION_NODES)
    }
    strong = strong_helpers
    if strong is None:
        strong = _local_assertion_helpers(
            tree, aliases, unittest_context=unittest_context
        )
    return {
        name
        for name, node in functions.items()
        if name not in strong
        and _meaningful_local_assertion(
            node,
            _scope_security_aliases(aliases, node),
            strong,
            unittest_context=unittest_context,
        )
    }


def _class_oracle_helpers(tree: ast.Module, aliases: dict, methods: set[int]) -> dict:
    result = {}
    for cls in (item for item in tree.body if isinstance(item, ast.ClassDef)):
        functions = [item for item in cls.body if isinstance(item, _FUNCTION_NODES)]
        context = any(id(item) in methods for item in functions)
        helpers = _local_assertion_helpers(
            ast.Module(body=functions, type_ignores=[]),
            aliases,
            unittest_context=context,
        )
        names = {"self." + name for name in helpers}
        result.update({id(method): names for method in functions})
    return result


def _nested_helper_definitions(test: ast.AST) -> dict[str, ast.AST] | None:
    definitions = {}
    for child in test.body:
        if not isinstance(child, _FUNCTION_NODES):
            continue
        if child.name in definitions:
            return None
        definitions[child.name] = child
    return definitions


def _nested_helper_names_are_unbound(test: ast.AST, definitions: dict) -> bool:
    names = set(definitions)
    for statement in test.body:
        if statement in definitions.values():
            continue
        if _bound_names(statement).intersection(names):
            return False
    for function in definitions.values():
        if _scope_parameters(function).intersection(names):
            return False
        for statement in function.body:
            if _bound_names(statement).intersection(names):
                return False
        if any(
            isinstance(child, (ast.Global, ast.Nonlocal))
            and names.intersection(child.names)
            for child in _iter_ast_nodes(function)
        ):
            return False
    return True


def _nested_helper_calls_assertion(
    nodes: list, definitions: dict, targets: set, aliases: dict
) -> bool:
    for call in nodes:
        if not isinstance(call, ast.Call):
            continue
        target = _call_name(call)
        if target not in targets or call.lineno <= definitions[target].lineno:
            continue
        if isinstance(definitions[target], ast.AsyncFunctionDef) and not isinstance(
            getattr(call, "_oracle_parent", None), ast.Await
        ):
            continue
        if _effective_assertion(call, aliases):
            return True
    return False


def _nested_helper_effective_names(
    definitions: dict, aliases: dict, inherited: set
) -> set[str]:
    candidates = {
        name for name, function in definitions.items() if not function.decorator_list
    }
    effective: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name in candidates - effective:
            function = definitions[name]
            scoped = _scope_security_aliases(aliases, function)
            nodes = _test_oracle_body_nodes(function, scoped)
            local_bindings = _scope_parameters(function)
            for statement in function.body:
                local_bindings.update(_bound_names(statement))
            safe_inherited = inherited - local_bindings
            if _strong_local_assertion(function, scoped, safe_inherited) or (
                _nested_helper_calls_assertion(nodes, definitions, effective, scoped)
            ):
                effective.add(name)
                changed = True
    return effective


def _nested_helper_inherited_names(
    test: ast.AST, definitions: dict, inherited: set
) -> set:
    safe = inherited - set(definitions)
    for statement in test.body:
        if statement not in definitions.values():
            safe -= _bound_names(statement)
    return safe


def _direct_nested_helper_calls(
    test: ast.AST, definitions: dict, effective: set, aliases: dict
) -> set[str]:
    body_nodes = _test_oracle_body_nodes(test, aliases)
    direct = set()
    for name, function in definitions.items():
        if name not in effective:
            continue
        for call in (child for child in body_nodes if isinstance(child, ast.Call)):
            if _call_name(call) != name or call.lineno <= function.lineno:
                continue
            if isinstance(function, ast.AsyncFunctionDef) and not isinstance(
                getattr(call, "_oracle_parent", None), ast.Await
            ):
                continue
            if _effective_assertion(call, aliases):
                direct.add(name)
    direct |= contracts._nested_async_runner_invocations(
        test, definitions, effective, aliases
    )
    direct.update(
        _directly_invoked_callback_names(body_nodes, definitions, effective, aliases)
    )
    return direct


def _directly_invoked_callback_names(body_nodes, definitions, effective, aliases):
    invoked = set()
    for name, function in definitions.items():
        parameter = _direct_callback_parameter(function)
        if parameter is None:
            continue
        for call in body_nodes:
            if not isinstance(call, ast.Call) or _call_name(call) != name:
                continue
            if call.lineno <= function.lineno:
                continue
            if not _effective_assertion(call, aliases):
                continue
            callback = _callback_argument(call, function, parameter)
            if callback in effective and definitions[callback].lineno < call.lineno:
                invoked.add(callback)
                invoked.add(name)
    return invoked


def _direct_callback_parameter(function):
    statements = [
        item
        for item in function.body
        if not (
            isinstance(item, ast.Expr)
            and isinstance(item.value, ast.Constant)
            and isinstance(item.value.value, str)
        )
    ]
    if not statements or not isinstance(statements[-1], (ast.Expr, ast.Return)):
        return None
    if any(
        not isinstance(item, (ast.Assign, ast.AnnAssign, ast.Expr))
        for item in statements[:-1]
    ):
        return None
    call = statements[-1].value
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
        return None
    if any(call.func.id in _bound_names(item) for item in statements[:-1]):
        return None
    return call.func.id if call.func.id in _scope_parameters(function) else None


def _callback_argument(call, function, parameter):
    from .review_integrity import callback_argument

    return callback_argument(call, function, parameter)


def _source_callback_parameters(function, methods, depth=0, aliases=None):
    """Resolve bounded first-party callback paths, excluding swallowed calls."""
    if depth >= 4 or function.decorator_list:
        return set()
    parameters = _scope_parameters(function)
    nodes = _test_oracle_body_nodes(function, {})
    if sum(isinstance(item, ast.Call) for item in nodes) > 128:
        return set()
    aliases = _scope_security_aliases(aliases or {}, function)
    invoked = _partial_callback_parameters(
        function, methods, nodes, depth, aliases or {}
    )
    for call in (item for item in nodes if isinstance(item, ast.Call)):
        if not _in_current_test_body(call) or not _effective_assertion(call, aliases):
            continue
        if isinstance(call.func, ast.Name) and call.func.id in parameters:
            if isinstance(
                getattr(call, "_oracle_parent", None), ast.Await
            ) and _callback_binding_preserved(
                nodes, call.func.id, call.lineno, methods, aliases
            ):
                invoked.add(call.func.id)
            continue
        target = methods.get(_call_name(call).removeprefix("self."))
        if target is None or not _call_name(call).startswith("self."):
            continue
        if isinstance(target, ast.AsyncFunctionDef) and not isinstance(
            getattr(call, "_oracle_parent", None), ast.Await
        ):
            continue
        for parameter in _source_callback_parameters(
            target, methods, depth + 1, aliases
        ):
            invoked.update(
                _forwarded_callback_names(
                    call, target, parameter, parameters, nodes, methods, aliases
                )
            )
    return invoked


def _forwarded_callback_names(
    call, target, parameter, parameters, nodes, methods, aliases
):
    names = [item.arg for item in [*target.args.posonlyargs, *target.args.args][1:]]
    values = [value.value for value in call.keywords if value.arg == parameter]
    if parameter in names and names.index(parameter) < len(call.args):
        values.append(call.args[names.index(parameter)])
    return {
        value.id
        for value in values
        if isinstance(value, ast.Name)
        and value.id in parameters
        and _callback_binding_preserved(nodes, value.id, call.lineno, methods, aliases)
    }


def _partial_callback_bindings(nodes, methods, aliases):
    bindings, invalid = {}, set()
    for statement in nodes:
        if not isinstance(
            statement, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)
        ):
            continue
        names = _bound_names(statement)
        call = getattr(statement, "value", None)
        target = None
        if (
            isinstance(call, ast.Call)
            and _normalized_call_name(call, aliases) == "functools.partial"
            and call.args
            and _name(call.args[0]).startswith("self.")
        ):
            target = methods.get(_name(call.args[0]).removeprefix("self."))
        if target is None or not _effective_assertion(call, aliases):
            invalid.update(names)
            continue
        for name in names:
            bindings.setdefault(name, []).append((target, call))
    return {name: values for name, values in bindings.items() if name not in invalid}


def _partial_callback_parameters(function, methods, nodes, depth, aliases):
    if depth >= 4:
        return set()
    bindings = _partial_callback_bindings(nodes, methods, aliases)
    invoked = set()
    for call in (item for item in nodes if isinstance(item, ast.Call)):
        if not isinstance(
            getattr(call, "_oracle_parent", None), ast.Await
        ) or not _effective_assertion(call, aliases):
            continue
        for target, partial in bindings.get(_call_name(call), ()):
            if partial.lineno >= call.lineno:
                continue
            names = [
                item.arg for item in [*target.args.posonlyargs, *target.args.args][1:]
            ]
            for parameter in _source_callback_parameters(
                target, methods, depth + 1, aliases
            ):
                if parameter in names and names.index(parameter) + 1 < len(
                    partial.args
                ):
                    value = partial.args[names.index(parameter) + 1]
                    if (
                        isinstance(value, ast.Name)
                        and value.id in _scope_parameters(function)
                        and _callback_binding_preserved(
                            nodes, value.id, partial.lineno, methods, aliases
                        )
                    ):
                        invoked.add(value.id)
    return invoked


def _callback_wrapper_preserves(method, parameter, aliases=None):
    definitions = _nested_helper_definitions(method) or {}
    returned = [item.value for item in method.body if isinstance(item, ast.Return)]
    if len(returned) != 1 or not isinstance(returned[0], ast.Name):
        return False
    wrapper = definitions.get(returned[0].id)
    if (
        not isinstance(wrapper, ast.AsyncFunctionDef)
        or wrapper.decorator_list
        or parameter in _scope_parameters(wrapper)
    ):
        return False
    if any(parameter in _bound_names(item) for item in method.body):
        return False
    aliases = _scope_security_aliases(aliases or {}, wrapper)
    nodes = _test_oracle_body_nodes(wrapper, aliases)
    return any(
        isinstance(item, ast.Call)
        and _call_name(item) == parameter
        and isinstance(getattr(item, "_oracle_parent", None), ast.Await)
        and _effective_assertion(item, aliases)
        and _callback_binding_preserved(nodes, parameter, item.lineno, {}, aliases)
        for item in nodes
    )


def _callback_binding_preserved(nodes, parameter, before, methods, aliases=None):
    for statement in nodes:
        if (
            not isinstance(
                statement, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)
            )
            or statement.lineno >= before
            or parameter not in _bound_names(statement)
        ):
            continue
        call = getattr(statement, "value", None)
        if (
            not isinstance(call, ast.Call)
            or not _call_name(call).startswith("self.")
            or len(call.args) != 1
            or not isinstance(call.args[0], ast.Name)
            or call.args[0].id != parameter
        ):
            return False
        method = methods.get(_call_name(call).removeprefix("self."))
        if method is None:
            return False
        names = [item.arg for item in [*method.args.posonlyargs, *method.args.args][1:]]
        if not names or not _callback_wrapper_preserves(method, names[0], aliases):
            return False
    return True


def _inherited_source_methods(cls, tree, depth=0):
    methods = {}
    if depth >= 4:
        return methods
    classes = {item.name: item for item in tree.body if isinstance(item, ast.ClassDef)}
    for base in cls.bases:
        if isinstance(base, ast.Name) and base.id in classes:
            methods.update(_inherited_source_methods(classes[base.id], tree, depth + 1))
    methods.update(
        {item.name: item for item in cls.body if isinstance(item, _FUNCTION_NODES)}
    )
    return methods


def _source_methods_are_stable(methods):
    if {
        "__getattribute__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
    } & methods.keys():
        return False
    for method in methods.values():
        for node in ast.walk(method):
            if isinstance(node, ast.Attribute) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                if _name(node.value) == "self" and node.attr in methods:
                    return False
            if isinstance(node, ast.Call) and _call_name(node) in {
                "setattr",
                "delattr",
            }:
                if node.args and _name(node.args[0]) == "self":
                    return False
    return True


def _source_callback_invokers(imports, snapshots, summaries=None):
    invokers = {}
    summaries = {} if summaries is None else summaries
    for local, (source, symbol) in imports.items():
        tree = snapshots.get(source)
        if tree is None or symbol is None:
            continue
        key = (source, symbol)
        if key in summaries:
            if summaries[key] is not None:
                invokers[local] = summaries[key]
            continue
        summaries[key] = None
        declarations = [
            item
            for item in tree.body
            if isinstance(item, ast.ClassDef) and item.name == symbol
        ]
        if len(declarations) != 1:
            continue
        methods = _inherited_source_methods(declarations[0], tree)
        if not _source_methods_are_stable(methods):
            continue
        function = methods.get("__call__")
        if not isinstance(function, ast.AsyncFunctionDef):
            continue
        parameters = [
            item.arg for item in [*function.args.posonlyargs, *function.args.args][1:]
        ]
        invoked = _source_callback_parameters(
            function, methods, aliases=_module_security_aliases(tree)
        )
        invokers[local] = {
            "parameters": parameters,
            "invoked": sorted(invoked),
            "source": source.as_posix(),
            "symbol": symbol,
            "virtual_dispatch": integrity.virtual_dispatch_defaults(
                methods, _module_security_aliases(tree), _effective_assertion
            ),
        }
        summaries[key] = invokers[local]
    return invokers


def _source_invoked_callbacks(test, invokers, strong, aliases):
    nodes = _test_oracle_body_nodes(test, aliases)
    constructors = {
        statement.targets[0].id: (
            invokers[_call_name(statement.value)],
            statement.lineno,
        )
        for statement in test.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and isinstance(statement.value, ast.Call)
        and _call_name(statement.value) in invokers
        and _call_name(statement.value).split(".", 1)[0] in aliases
    }
    for call in (item for item in nodes if isinstance(item, ast.Call)):
        binding = constructors.get(_call_name(call))
        if (
            binding is None
            or not isinstance(getattr(call, "_oracle_parent", None), ast.Await)
            or not _effective_assertion(call, aliases)
        ):
            continue
        profile, constructed_at = binding
        if (
            call.lineno <= constructed_at
            or _name_rebound(nodes, _call_name(call), constructed_at, call.lineno)
            or _click_receiver_mutated(test, _call_name(call))
        ):
            continue
        for parameter in profile["invoked"]:
            index = (
                profile["parameters"].index(parameter)
                if parameter in profile["parameters"]
                else len(call.args)
            )
            arguments = [item.value for item in call.keywords if item.arg == parameter]
            if index < len(call.args):
                arguments.append(call.args[index])
            if any(
                isinstance(item, ast.Name) and item.id in strong for item in arguments
            ):
                return True
    return False


def _local_virtual_dispatch_classes(test, invokers, aliases, helpers):
    profiles = {}
    for cls in (item for item in test.body if isinstance(item, ast.ClassDef)):
        if (
            len(cls.bases) != 1
            or cls.decorator_list
            or cls.keywords
            or _click_receiver_mutated(test, cls.name)
        ):
            continue
        if any(
            not isinstance(
                item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Pass, ast.Expr)
            )
            for item in cls.body
        ):
            continue
        if any(
            item is not cls
            and isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == cls.name
            for item in ast.walk(test)
        ):
            continue
        base = _name(cls.bases[0])
        profile = invokers.get(base, {}).get("virtual_dispatch", {})
        if (
            not profile
            or base.split(".", 1)[0] not in aliases
            or _click_receiver_mutated(test, base)
        ):
            continue
        if any(
            isinstance(item, ast.Expr) and not isinstance(item.value, ast.Constant)
            for item in cls.body
        ):
            continue
        methods = {
            item.name: item for item in cls.body if isinstance(item, _FUNCTION_NODES)
        }
        if (
            "__init__" in methods
            or "__call__" in methods
            or not _source_methods_are_stable(methods)
            or any(method.decorator_list for method in methods.values())
            or set(methods) - set(profile["methods"])
        ):
            continue
        if any(
            _strong_local_assertion(
                methods[name], _scope_security_aliases(aliases, methods[name]), helpers
            )
            for name in profile["methods"]
            if name in methods and not methods[name].decorator_list
        ):
            profiles[cls.name] = {"profile": profile, "line": cls.lineno}
    return profiles


def _virtual_dispatch_constructor(statement, profiles, nodes):
    if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
        return None
    targets = (
        statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    )
    call = statement.value
    if (
        len(targets) != 1
        or not isinstance(targets[0], ast.Name)
        or not isinstance(call, ast.Call)
    ):
        return None
    declared = profiles.get(_call_name(call))
    if (
        declared is None
        or call.keywords
        or len(call.args) != declared["profile"]["required_arguments"]
    ):
        return None
    if statement.lineno <= declared["line"] or _name_rebound(
        nodes, _call_name(call), declared["line"], statement.lineno
    ):
        return None
    return targets[0].id


def _local_virtual_dispatch_oracle(test, invokers, aliases, helpers):
    profiles = _local_virtual_dispatch_classes(test, invokers, aliases, helpers)
    if not profiles:
        return False
    nodes = _test_oracle_body_nodes(test, aliases)
    for statement in test.body:
        name = _virtual_dispatch_constructor(statement, profiles, nodes)
        if name is None or _click_receiver_mutated(test, name):
            continue
        for call in (item for item in nodes if isinstance(item, ast.Call)):
            if _call_name(call) != name or not isinstance(
                getattr(call, "_oracle_parent", None), ast.Await
            ):
                continue
            if (
                statement.lineno < call.lineno
                and not _name_rebound(nodes, name, statement.lineno, call.lineno)
                and _effective_assertion(call, aliases)
                and _virtual_call_matches_guards(call, statement, profiles, nodes)
            ):
                return True
    return False


def _virtual_call_matches_guards(call, constructed, profiles, nodes):
    guards = profiles[_call_name(constructed.value)]["profile"].get("guards", [])
    for guard in guards:
        argument = next(
            (k.value for k in call.keywords if k.arg == guard["parameter"]), None
        )
        if guard["index"] < len(call.args):
            argument = call.args[guard["index"]]
        if isinstance(argument, ast.Name):
            bindings = [
                n
                for n in nodes
                if isinstance(n, (ast.Assign, ast.AnnAssign))
                and argument.id in _bound_names(n)
                and n.lineno < call.lineno
            ]
            if len(bindings) != 1 or bindings[0] not in getattr(
                call._oracle_scope, "body", []
            ):
                return False
            if not _virtual_scope_binding_safe(nodes, argument.id, bindings[0], call):
                return False
            argument = bindings[0].value
        try:
            value = ast.literal_eval(argument)
        except (ValueError, TypeError, SyntaxError):
            return False
        if not isinstance(value, dict) or value.get(guard["key"]) != guard["value"]:
            return False
    return True


def _virtual_scope_binding_safe(nodes, name, bound, call):
    start, end = (bound.lineno, bound.col_offset), (call.lineno, call.col_offset)
    for node in nodes:
        if (
            not start
            < (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
            < end
        ):
            continue
        if isinstance(
            node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr, ast.Delete)
        ) and name in _bound_names(node):
            return False
        if isinstance(node, (ast.Subscript, ast.Attribute)) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            if _name(node.value).split(".", 1)[0] == name:
                return False
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and _name(node.value) == name:
            return False
        if isinstance(node, ast.Call) and any(
            _name(arg) == name
            for arg in [*node.args, *(k.value for k in node.keywords)]
        ):
            return False
    return True


def _proven_dispatch_assertion(test, aliases, helpers, apps, invokers):
    from .review_integrity import flask_invoked_callbacks, registered_callback_oracle

    if registered_callback_oracle(
        test,
        aliases,
        lambda fn, scope: _strong_local_assertion(
            fn, _scope_security_aliases(scope, fn), helpers
        ),
        _effective_assertion,
    ):
        return True
    if _local_virtual_dispatch_oracle(test, invokers, aliases, helpers):
        return True
    definitions = _nested_helper_definitions(test)
    if not definitions or not _nested_helper_names_are_unbound(test, definitions):
        return False
    strong = {
        name
        for name, function in definitions.items()
        if _strong_local_assertion(
            function, _scope_security_aliases(aliases, function), helpers
        )
    }
    undecorated = {name for name in strong if not definitions[name].decorator_list}
    return bool(
        flask_invoked_callbacks(test, aliases, apps, strong, _effective_assertion)
    ) or _source_invoked_callbacks(test, invokers, undecorated, aliases)


def _flask_context_apps(path, tree, snapshots):
    declared = {}
    sources = sorted(
        (
            source
            for source in snapshots
            if source.name == "conftest.py"
            and path.parent.is_relative_to(source.parent)
        ),
        key=lambda source: len(source.parts),
    )
    for source in sources:
        target = snapshots[source]
        declared.update(
            integrity.flask_fixture_apps(target, _module_security_aliases(target))
        )
    declared.update(integrity.flask_fixture_apps(tree, _module_security_aliases(tree)))
    return {name for name, trusted in declared.items() if trusted}


def _invoked_nested_assertion_helpers(
    test: ast.AST, aliases: dict[str, str], inherited: set[str]
) -> set[str]:
    """Find directly invoked nested helpers with effective assertions."""
    if not isinstance(test, _FUNCTION_NODES):
        return set()
    definitions = _nested_helper_definitions(test)
    if not definitions or not _nested_helper_names_are_unbound(test, definitions):
        return set()
    inherited = _nested_helper_inherited_names(test, definitions, inherited)
    effective = _nested_helper_effective_names(definitions, aliases, inherited)
    return _direct_nested_helper_calls(test, definitions, effective, aliases)


def _oracle_import_source(
    root: Path,
    path: Path,
    node: ast.AST,
    module: str,
    eligible: set[Path] | dict[Path, Path],
    imported: str | None = None,
) -> Path | None:
    root_abs = root.resolve()
    eligible_abs = (
        eligible if isinstance(eligible, dict) else {p.resolve(): p for p in eligible}
    )
    parts = module.split(".") if module else []
    if isinstance(node, ast.ImportFrom) and node.level:
        base = path.parent
        for _ in range(node.level - 1):
            base = base.parent
        bases = [base]
    else:
        bases = [path.parent, root, root / "src"]
    child_matches = set()
    package_matches = set()
    for base in bases:
        target = base.joinpath(*parts)
        child_choices = []
        if isinstance(node, ast.ImportFrom) and imported and imported != "*":
            child = target / imported
            child_choices.extend([child.with_suffix(".py"), child / "__init__.py"])
        package_choices = (
            [target.with_suffix(".py"), target / "__init__.py"]
            if parts
            else [target / "__init__.py"]
        )
        for choice in child_choices + package_choices:
            if not choice.is_file():
                continue
            resolved = choice.resolve()
            if (
                resolved.is_relative_to(root_abs)
                and resolved in eligible_abs
                and choice.is_file()
                and not choice.is_symlink()
            ):
                target_set = (
                    child_matches if choice in child_choices else package_matches
                )
                target_set.add(eligible_abs[resolved])
    if child_matches:
        return next(iter(child_matches)) if len(child_matches) == 1 else None
    return next(iter(package_matches)) if len(package_matches) == 1 else None


def _oracle_imports(
    root: Path, path: Path, tree: ast.Module, eligible: set[Path] | dict[Path, Path]
) -> dict:
    imports = {}
    for node in tree.body:
        if not isinstance(node, (ast.ImportFrom, ast.Import)):
            continue
        for item in node.names:
            if item.name == "*":
                continue
            module = (
                (node.module or "") if isinstance(node, ast.ImportFrom) else item.name
            )
            source = _oracle_import_source(
                root,
                path,
                node,
                module,
                eligible,
                item.name if isinstance(node, ast.ImportFrom) else None,
            )
            if source is None:
                continue
            alias = item.asname or item.name
            imports[alias] = (
                source,
                item.name if isinstance(node, ast.ImportFrom) else None,
            )
    return imports


def _oracle_source_inputs(
    root: Path, files: list[Path]
) -> tuple[dict, list, list, bool]:
    return contracts._oracle_source_inputs(
        root,
        files,
        _security_source_bytes,
        local_file,
        _measure_hash,
        sha256,
        RuntimeAuditError,
        MAX_BYTES,
        16 * 1024 * 1024,
    )


def _oracle_snapshots(root: Path, files: list[Path], source_bytes: dict) -> dict:
    return contracts._oracle_source_snapshots(
        root,
        files,
        source_bytes,
        _security_source_bytes,
        _measure_parse,
        RuntimeAuditError,
        MAX_BYTES,
    )


def _declared_typecheck_sources(
    root: Path, files: list[Path]
) -> tuple[set, list, dict, bool]:
    """Preserve the existing selector contract through the intent-quality module."""
    return contracts._declared_typecheck_sources(
        root,
        files,
        _security_source_bytes,
        local_file,
        _relative_path,
        RuntimeAuditError,
        MAX_BYTES,
        MAX_PATHS,
    )


def _oracle_context_cache_key(root: Path, manifest: list, config_identity: dict) -> str:
    from . import test_oracle_misuse as oracle_misuse
    from . import test_callback_closure
    from . import mock_fixture_provenance
    from . import mock_fixture_allocations
    from .context_efficiency import (
        _consume_security_snapshots,
        _populate_oracle_database_context,
        _read_bounded_workspace_source,
        _scan_missing_security_snapshot,
        async_runner_fixture_helpers,
        protocol_call_helpers,
    )

    helpers = (
        ast.parse,
        _build_oracle_context,
        _completion_only_oracle,
        integrity._completion_only_oracle,
        integrity._builtin_repr_names_shadowed,
        integrity._security_module_scope,
        integrity._security_scope_local_names,
        contracts._static_type_edges,
        contracts.native_import_profile,
        contracts.import_configuration,
        contracts.new_import_views,
        contracts.import_context_metadata,
        _security_source_bytes,
        _read_bounded_workspace_source,
        _consume_security_snapshots,
        _populate_oracle_database_context,
        _scan_missing_security_snapshot,
        local_file,
        _measure_parse,
        RuntimeAuditError,
        _click_runner_fixtures,
        _scope_security_aliases,
        _module_security_aliases,
        _ty_assertion_helpers,
        _oracle_imports,
        _oracle_import_source,
        _imported_oracle_helpers,
        _imported_weak_oracle_helpers,
        _imported_oracle_helper_sets,
        _imported_unittest_mixins,
        _unittest_testcase_classes,
        _class_oracle_helpers,
        _oracle_snapshots,
        contracts._oracle_source_snapshots,
        _oracle_source_inputs,
        contracts._oracle_source_inputs,
        _measure_hash,
        _declared_typecheck_sources,
        contracts._declared_typecheck_sources,
        contracts._ty_sources,
        contracts._ty_invocation_profile,
        contracts._ty_safe_passenv,
        contracts._ty_external_config_state,
        contracts._ty_config_scope,
        contracts._ty_assertion_rules,
        contracts._ty_selected_paths,
        contracts._ty_paths,
        contracts._ty_default_excluded,
        contracts._ty_assertion_provider_mutated,
        contracts._ty_global_git_configuration,
        contracts._ty_ignored_paths,
        contracts._ty_path_is_ignored,
        contracts._ty_ignore_file_patterns,
        contracts._ty_parse_ignore_lines,
        contracts._ty_matches_ignore,
        _source_callback_invokers,
        _source_methods_are_stable,
        _source_callback_parameters,
        _forwarded_callback_names,
        _partial_callback_bindings,
        _partial_callback_parameters,
        _callback_binding_preserved,
        _callback_wrapper_preserves,
        integrity.flask_fixture_apps,
        integrity.flask_invoked_callbacks,
        integrity.virtual_dispatch_defaults,
        _flask_context_apps,
        _local_assertion_helpers,
        _local_weak_assertion_helpers,
        oracle_misuse._constant_truth_value,
        oracle_misuse._static_expression,
        oracle_misuse.always_truthy_assertion_reason,
        oracle_misuse.discarded_comparison_reason,
        oracle_misuse.retain_local_oracle_diagnostics,
        oracle_misuse.weak_assertion_reason,
        _is_oracle_helper_name,
        _oracle_context_cache_eligible,
        _project_oracle_context,
        integrity.NativeOraclePayload.__new__,
        integrity.NativeOraclePayload.valid,
    )
    helpers += test_callback_closure.CACHE_HELPERS
    helpers += mock_fixture_provenance.CACHE_HELPERS
    helpers += mock_fixture_allocations.CACHE_HELPERS
    helpers += async_runner_fixture_helpers() + protocol_call_helpers()
    helpers += (integrity.source_binding_helpers, *integrity.source_binding_helpers())
    helpers += integrity.fixed_program_workspace_helpers()
    helpers += contracts.project_contract_helpers() + tuple(
        getattr(integrity, name)
        for name in (
            "oracle_configuration",
            "bind_benchmark_context",
            "_structural_oracle_context",
        )
    )
    identity = {
        "schema": integrity.credential_context_cache_schema(),
        "root": root.resolve().as_posix(),
        "sources": manifest,
        "config": config_identity,
        "source_limit": MAX_BYTES,
        "source_retention_limit": 16 * 1024 * 1024,
        "python": [sys.implementation.name, *sys.version_info[:3]],
        "helpers": [id(helper) for helper in helpers],
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()


def _imported_oracle_helper_sets(
    imports: dict, snapshots: dict, aliases: dict, summary_cache: dict | None = None
) -> tuple[set[str], set[str]]:
    helpers, weak_helpers = set(), set()
    for local, (source, symbol) in imports.items():
        tree = snapshots.get(source)
        if tree is None:
            continue
        summary = summary_cache.get(tree) if summary_cache is not None else None
        if summary is None:
            raw_aliases = _module_security_aliases(tree)
            module_aliases = _scope_security_aliases(raw_aliases, tree)
            strong = _local_assertion_helpers(tree, module_aliases)
            weak = _local_weak_assertion_helpers(
                tree, module_aliases, strong_helpers=strong
            )
            exported = {
                name
                for name, target in raw_aliases.items()
                if target in {"pytest.raises", "pytest.warns"}
            }
            summary = module_aliases, strong, weak, exported
            if summary_cache is not None:
                summary_cache[tree] = summary
        _, strong, weak, exported = summary
        for names, result in (
            (
                {name for name in strong if _is_oracle_helper_name(name)} | exported,
                helpers,
            ),
            ({name for name in weak if _is_oracle_helper_name(name)}, weak_helpers),
        ):
            if symbol in names:
                result.add(aliases.get(local, local))
            elif symbol is None or symbol not in names:
                result.update(aliases.get(local, local) + "." + name for name in names)
    return helpers, weak_helpers


def _imported_oracle_helpers(
    imports: dict, snapshots: dict, aliases: dict, *, summary_cache: dict | None = None
) -> set[str]:
    return _imported_oracle_helper_sets(imports, snapshots, aliases, summary_cache)[0]


def _imported_weak_oracle_helpers(
    imports: dict, snapshots: dict, aliases: dict, *, summary_cache: dict | None = None
) -> set[str]:
    return _imported_oracle_helper_sets(imports, snapshots, aliases, summary_cache)[1]


def _imported_unittest_mixins(tree: ast.Module, aliases: dict, imports: dict) -> list:
    _classes, base_names, testcase_classes = _unittest_testcase_classes(tree, aliases)
    references = []
    for cls in (item for item in tree.body if isinstance(item, ast.ClassDef)):
        if cls.name not in testcase_classes:
            continue
        for base_name in base_names.get(cls.name, ()):
            reference = imports.get(base_name) or imports.get(
                base_name.rsplit(".", 1)[-1]
            )
            if reference and reference[1]:
                references.append(reference)
    return references


def _imported_pytest_bases(tree, imports):
    references = []
    for cls in (item for item in tree.body if isinstance(item, ast.ClassDef)):
        if not cls.name.startswith("Test") or any(
            isinstance(member, _FUNCTION_NODES) and member.name == "__init__"
            for member in cls.body
        ):
            continue
        for base in cls.bases:
            reference = imports.get(_name(base).rsplit(".", 1)[-1])
            if reference and reference[1]:
                references.append(reference)
    return references


def _bind_imported_pytest_bases(tree, imports, snapshots, contexts):
    for source, symbol in _imported_pytest_bases(tree, imports):
        target_tree = snapshots.get(source)
        target_class = next(
            (
                item
                for item in getattr(target_tree, "body", ())
                if isinstance(item, ast.ClassDef) and item.name == symbol
            ),
            None,
        )
        if target_class is None or source not in contexts:
            continue
        contexts[source]["pytest_inherited"].update(
            f"{symbol}.{method.name}"
            for method in target_class.body
            if isinstance(method, _FUNCTION_NODES) and method.name.startswith("test_")
        )


def _pytest_inherited_method_ids(tree, inherited_names):
    return {
        id(method)
        for cls in tree.body
        if isinstance(cls, ast.ClassDef)
        for method in cls.body
        if isinstance(method, _FUNCTION_NODES)
        and f"{cls.name}.{method.name}" in inherited_names
    }


def _oracle_context_cache_eligible(cache_enabled, source_cacheable, config_cacheable):
    """Return whether both oracle input groups allow a reusable projection."""
    return cache_enabled and source_cacheable and config_cacheable


def _project_oracle_context(
    root: Path,
    files: list[Path],
    *,
    cache_enabled: bool = True,
    collection_identity: dict | None = None,
    python_inventory_out: list | None = None,
    database_context_out: dict | None = None,
    security_snapshot_consumer=None,
) -> tuple[dict, list, list, dict]:
    """Resolve local imports and return retained bytes without executing repository code."""
    if database_context_out is not None:
        database_context_out.clear()
    source_bytes, source_bindings, manifest, source_cacheable = _oracle_source_inputs(
        root, files
    )
    retained_paths = {path.relative_to(root).as_posix() for path in source_bytes}
    python_inventory = [
        {
            "path": item["path"],
            "state": item["state"],
            "retained": item["path"] in retained_paths,
        }
        for item in manifest
        if item["path"].lower().endswith(".py")
    ]
    if python_inventory_out is not None:
        python_inventory_out.extend(python_inventory)
    (
        typecheck_sources,
        config_bindings,
        config_identity,
        config_cacheable,
        benchmarks,
    ) = integrity.oracle_configuration(
        root, files, _declared_typecheck_sources, _security_source_bytes, MAX_BYTES
    )
    config_identity = contracts.import_configuration(
        config_identity, collection_identity, len(files)
    )
    bindings = source_bindings + config_bindings
    cache_key = _oracle_context_cache_key(root, manifest, config_identity)
    if _oracle_context_cache_eligible(
        cache_enabled, source_cacheable, config_cacheable
    ):
        cached = _oracle_context_cache_read(cache_key)
        if cached is not None:
            contexts, edges = cached
            return contexts, bindings, edges, source_bytes
    snapshots = contracts.bound_snapshots(root, files, source_bytes, source_bindings)
    file_paths = set(files)
    source_hashes = {
        root / binding["path"]: binding["sha256"] for binding in source_bindings
    }
    for path, tree in tuple(snapshots.items()):
        if path not in file_paths:
            snapshots.pop(path)
            continue
        if isinstance(tree, ast.Module) and getattr(
            tree, "_oracle_source_sha256", None
        ) == source_hashes.get(path):
            continue
        snapshots.pop(path)
        snapshots.update(
            contracts._oracle_source_snapshots(
                root,
                [path],
                source_bytes,
                _security_source_bytes,
                _measure_parse,
                RuntimeAuditError,
                MAX_BYTES,
            )
        )
    snapshot_fingerprints = {
        path: _oracle_tree_fingerprint(tree) for path, tree in snapshots.items()
    }
    from .context_efficiency import _populate_oracle_database_context

    _populate_oracle_database_context(
        database_context_out,
        root,
        source_bytes,
        _security_source_bytes,
        python_inventory,
        snapshots,
    )
    ty_identity = config_identity["typecheck"].get("ty", {})
    ty_sources = {root / item for item in ty_identity.get("selected", [])}
    import_views = contracts.new_import_views(len(files))
    contexts, edges = _build_oracle_context(
        root, files, snapshots, typecheck_sources, ty_sources, import_views
    )
    integrity.bind_benchmark_context(contexts, snapshots, benchmarks)
    resolved = contracts._project_import_views(import_views, snapshots)
    integrity.bind_fixed_program_workspace(
        root, contexts, snapshots, files, source_bytes, resolved
    )
    contracts.bind_project_contracts(root, snapshots, contexts, edges, resolved)
    edges += contracts._static_type_edges(
        root, typecheck_sources | ty_sources, config_bindings, ty_sources
    )
    if _oracle_context_cache_eligible(
        cache_enabled, source_cacheable, config_cacheable
    ):
        _oracle_context_cache_write(cache_key, contexts, edges)
    if security_snapshot_consumer is not None:
        try:
            security_snapshot_consumer(
                snapshots, snapshot_fingerprints, contexts, source_bytes
            )
        finally:
            snapshots.clear()
    return contexts, bindings, edges, source_bytes


def _build_oracle_context(
    root: Path,
    files: list[Path],
    snapshots: dict,
    typecheck_sources: set,
    ty_sources: set | None = None,
    import_views: dict | None = None,
) -> tuple[dict, list]:
    from . import mock_fixture_provenance
    from .context_efficiency import async_runner_fixture_context, protocol_call_context

    async_fixtures = async_runner_fixture_context(root, files, snapshots)
    protocols = protocol_call_context(root, files, snapshots)
    fixture_sources = [
        (
            path,
            _click_runner_fixtures(
                tree, _scope_security_aliases(_module_security_aliases(tree), tree)
            ),
        )
        for path, tree in snapshots.items()
        if path.name == "conftest.py"
    ]
    fixture_sources.sort(key=lambda item: len(item[0].parts))
    mock_fixture_sources = {
        path: mock_fixture_provenance.fixture_bindings_for_source(tree)
        for path, tree in snapshots.items()
    }
    contexts = {
        path: {
            "helpers": set(),
            "weak_helpers": set(),
            "mixins": set(),
            "pytest_inherited": set(),
        }
        for path in snapshots
    }
    edges = set()
    callback_summaries = {}
    helper_summaries = {}
    eligible = {path.resolve(): path for path in files}
    for path, tree in snapshots.items():
        caller = path.relative_to(root).as_posix()
        contexts[path]["protocol_observations"] = protocols.get(caller, {})
        aliases = _scope_security_aliases(_module_security_aliases(tree), tree)
        contexts[path]["async_runner_fixtures"] = async_fixtures.get(
            path.relative_to(root).as_posix(), {}
        )
        contexts[path]["mock_fixture_provenance"] = (
            mock_fixture_provenance.fixtures_for_file(path, mock_fixture_sources)
        )
        fixtures = {}
        for source, declared in fixture_sources:
            if path.parent.is_relative_to(source.parent):
                fixtures.update(declared)
        fixtures.update(_click_runner_fixtures(tree, aliases))
        contexts[path]["click_runners"] = {
            name for name, trusted in fixtures.items() if trusted
        }
        contexts[path]["typecheck"] = path in typecheck_sources or path in (
            ty_sources or ()
        )
        contexts[path]["flask_apps"] = _flask_context_apps(path, tree, snapshots)
        imports = _oracle_imports(root, path, tree, eligible)
        contracts._capture_project_imports(import_views, path, imports, eligible)
        contexts[path].update(
            integrity._structural_oracle_context(tree, imports, snapshots)
        )
        contexts[path]["callback_invokers"] = _source_callback_invokers(
            imports, snapshots, callback_summaries
        )
        contexts[path]["helpers"], contexts[path]["weak_helpers"] = (
            _imported_oracle_helper_sets(imports, snapshots, aliases, helper_summaries)
        )
        edges.update(
            (
                caller,
                Path(profile["source"]).relative_to(root).as_posix(),
                "callback_parameter",
                local + "." + parameter,
                "source_resolved",
            )
            for local, profile in contexts[path]["callback_invokers"].items()
            for parameter in profile["invoked"]
        )
        edges.update(
            (
                caller,
                Path(profile["source"]).relative_to(root).as_posix(),
                "default_virtual_dispatch",
                local + "." + method,
                "source_resolved",
            )
            for local, profile in contexts[path]["callback_invokers"].items()
            for method in profile.get("virtual_dispatch", {}).get("methods", [])
        )
        for local, (source, symbol) in imports.items():
            target = source.relative_to(root).as_posix()
            target_tree = snapshots.get(source)
            if target_tree is None:
                continue
            _, strong_summary, weak_summary, exported_assertions = helper_summaries[
                target_tree
            ]
            strong_names = {
                name for name in strong_summary if _is_oracle_helper_name(name)
            } | exported_assertions
            weak_names = {name for name in weak_summary if _is_oracle_helper_name(name)}
            selected = (
                [symbol]
                if symbol in strong_names
                else [f"{local}.{name}" for name in strong_names]
            )
            for resolved_symbol in selected:
                edges.add(
                    (caller, target, "assertion_helper", resolved_symbol, "strong")
                )
            selected_weak = (
                [symbol]
                if symbol in weak_names
                else [f"{local}.{name}" for name in weak_names]
            )
            for resolved_symbol in selected_weak:
                edges.add((caller, target, "assertion_helper", resolved_symbol, "weak"))
        for source, symbol in _imported_unittest_mixins(tree, aliases, imports):
            if source in contexts:
                contexts[source]["mixins"].add(symbol)
                edges.add(
                    (
                        path.relative_to(root).as_posix(),
                        source.relative_to(root).as_posix(),
                        "unittest_mixin",
                        symbol,
                        "trusted",
                    )
                )
        _bind_imported_pytest_bases(tree, imports, snapshots, contexts)
    edges = [
        {
            "caller": caller,
            "target": target,
            "kind": kind,
            "symbol": symbol,
            "strength": strength,
        }
        for caller, target, kind, symbol, strength in sorted(edges)
    ]
    return contexts, edges


def _weak_assertion_reason(
    node: ast.AST, aliases: dict[str, str] | None = None
) -> str | None:
    from .test_oracle_misuse import weak_assertion_reason

    return weak_assertion_reason(
        node, aliases or {}, _universal_type_check, _mock_argument_oracle
    )


def _universal_type_check(node: ast.Call) -> bool:
    from .review_integrity import _builtin_repr_is_call, _builtin_repr_names_shadowed

    return (
        _builtin_repr_is_call(node, "isinstance", 2)
        and isinstance(node.args[1], ast.Name)
        and node.args[1].id == "object"
        and not _builtin_repr_names_shadowed(node, {"isinstance", "object"})
    )


def _weak_test_oracle_finding(
    relative: str,
    node: ast.AST,
    aliases: dict[str, str],
    helper_names: set[str] | None = None,
    *,
    unittest_context: bool = False,
    weak_helper_names: set[str] | None = None,
) -> dict[str, Any] | None:
    if not isinstance(node, _FUNCTION_NODES) or not node.name.startswith("test_"):
        return None
    if _test_oracle_exempt(node, aliases):
        return None
    nodes = _test_oracle_body_nodes(node, aliases)
    from . import test_oracle_misuse as oracle_misuse
    from . import test_callback_closure
    from . import mock_fixture_provenance

    uninvoked = test_callback_closure.uninvoked_click_callback(
        node, aliases, helper_names
    )

    weak = [
        (
            child,
            _weak_assertion_reason(
                child.test if isinstance(child, ast.Assert) else child, aliases
            ),
        )
        for child in nodes
        if isinstance(child, ast.Assert)
        or _assertion_call(
            child, aliases, helper_names, unittest_context=unittest_context
        )
    ]
    weak.extend(
        (child, "delegated helper exposes only a weak assertion")
        for child in nodes
        if isinstance(child, ast.Call)
        and _normalized_call_name(child, aliases) in (weak_helper_names or set())
    )
    weak.extend(
        (child, reason)
        for child in nodes
        if (reason := oracle_misuse.discarded_comparison_reason(child)) is not None
    )
    weak.extend(mock_fixture_provenance.inert_fixture_assertions(nodes, aliases))
    if uninvoked is not None:
        weak.append(uninvoked)
    weak = [(child, reason) for child, reason in weak if reason]
    strong = bool(
        _local_assertion_nodes(
            node,
            aliases,
            helper_names,
            unittest_context=unittest_context,
            strong=True,
            nodes=nodes,
        )
    )
    if strong:
        weak = oracle_misuse.retain_local_oracle_diagnostics(weak) + [
            (child.value, "uninvoked mock assertion attribute")
            for child in nodes
            if isinstance(child, ast.Expr)
            and isinstance(child.value, ast.Attribute)
            and _mock_argument_oracle(child.value, aliases, uncalled=True)
        ]
    if not weak:
        return None
    reasons = sorted({reason for _, reason in weak})
    message = "; ".join(reasons)
    if not strong:
        message += ". Assert the independently expected value or state"
    return _security_finding(
        "QUALITY_WEAK_TEST_ORACLE",
        relative,
        weak[0][0],
        message + ".",
        "MEDIUM",
        symbol=node.name,
        reasons=reasons,
        evidence_scope="local_statement_semantics",
        execution_state="NOT_ESTABLISHED",
        whole_test_oracle="UNASSESSED",
    )


def _hollow_test_finding(
    relative: str,
    node: ast.AST,
    aliases: dict[str, str],
    helper_names: set[str] | None = None,
    *,
    unittest_context: bool = False,
    oracle_context: dict | None = None,
) -> dict[str, Any] | None:
    if not isinstance(node, _FUNCTION_NODES) or not node.name.startswith("test_"):
        return None
    from .review_integrity import structural_oracle_finding
    from .context_efficiency import _protocol_annotate_finding

    oracle = structural_oracle_finding(node, relative, oracle_context or {})
    if _test_oracle_exempt(node, aliases) or oracle is True:
        return None
    if isinstance(oracle, dict):
        return oracle
    if _meaningful_local_assertion(
        node, aliases, helper_names, unittest_context=unittest_context
    ) or any(
        isinstance(child, ast.Call)
        and isinstance(child.func, ast.Name)
        and child.func.id in (helper_names or set())
        and _effective_assertion(child, aliases)
        for child in _test_oracle_body_nodes(node, aliases)
    ):
        return None
    finding = _security_finding(
        "QUALITY_UNKNOWN_TEST_ORACLE",
        relative,
        node,
        "No recognized local oracle; delegated behavior and fixture lifecycle remain unverified.",
        "INFO",
        symbol=node.name,
        state="INCOMPLETE",
        evidence_state="UNKNOWN",
        candidate_rule="QUALITY_HOLLOW_TEST",
        native_assertion_probe=integrity.native_test_probe(relative, node),
        missing_evidence="meaningful oracle and fixture/lifecycle closure",
    )
    return _protocol_annotate_finding(finding, node, oracle_context or {})


def _has_manual_failure(node: ast.AST, aliases: dict[str, str]) -> bool:
    return any(
        isinstance(child, (ast.Raise, ast.With))
        for child in _assertion_nodes(node, aliases)
    )


def _test_oracle_exempt(node: ast.AST, aliases: dict[str, str]) -> bool:
    return _unconditionally_skipped_test(node) or _performance_benchmark_test(
        node, aliases
    )


def _tenant_contract_calls(value: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, tuple) or len(value) > MAX_RULES:
        raise ReviewAuditError(
            "Tenant read calls must be a bounded tuple of qualified names."
        )
    if any(not isinstance(x, str) or not NAME.fullmatch(x) for x in value):
        raise ReviewAuditError("Tenant read calls must contain qualified Python names.")
    return tuple(sorted(set(value)))


def _tenant_contract_bindings(
    values: tuple[str, ...], calls: tuple[str, ...]
) -> dict[str, tuple[str, ...]]:
    """Validate declared call-argument to enclosing-parameter tenant bindings."""
    if not isinstance(values, tuple) or len(values) > MAX_RULES:
        raise ReviewAuditError("Tenant read bindings must be a bounded tuple.")
    result: dict[str, list[str]] = {}
    seen: set[str] = set()
    for value in values:
        call, binding = _tenant_binding_entry(value, calls, seen)
        if call in result:
            raise ReviewAuditError(
                "Each read call may have only one tenant argument binding."
            )
        result.setdefault(call, []).append(binding)
    return {call: tuple(bindings) for call, bindings in sorted(result.items())}


def load_tenant_read_contract(
    root: Path, path: str = ".factory/tenant-read-contract.json"
) -> tuple[tuple[str, ...], tuple[str, ...], dict[str, Any]]:
    """Load a bounded, workspace-contained tenant-read declaration for CLI audits."""
    workspace = Path(root).resolve()
    relative = _relative_path(path).as_posix()
    contract_path = (workspace / relative).resolve()
    if not contract_path.is_relative_to(workspace):
        raise ReviewAuditError("Tenant-read contract must remain inside the workspace.")
    if not contract_path.exists():
        return (), (), {"path": relative, "state": "missing", "policy_applies": False}
    try:
        data, evidence = _read(workspace, relative)
        contract = json.loads(data, object_pairs_hook=_unique_fields)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReviewAuditError(f"Invalid tenant-read contract: {exc}") from exc
    if not isinstance(contract, dict) or set(contract) != {"schema", "reads"}:
        raise ReviewAuditError("Invalid tenant-read contract schema or fields.")
    if contract.get("schema") == "factory.tenant-read-contract.v2":
        evidence["scoped_reads"] = _tenant_scoped_entries(workspace, contract["reads"])
        evidence["policy_applies"] = False
        evidence["state"] = "loaded"
        return (), (), evidence
    if contract.get("schema") != TENANT_CONTRACT_SCHEMA:
        raise ReviewAuditError("Invalid tenant-read contract schema or fields.")
    calls, bindings = _tenant_contract_entries(contract["reads"])
    normalized_calls = _tenant_contract_calls(calls)
    normalized_bindings = _tenant_contract_bindings(bindings, normalized_calls)
    flattened = tuple(
        f"{call}={binding}"
        for call, values in normalized_bindings.items()
        for binding in values
    )
    evidence["policy_applies"] = True
    evidence["state"] = "loaded"
    return normalized_calls, flattened, evidence


def _tenant_scoped_entries(workspace: Path, value: Any) -> dict:
    """Validate exact file scopes without excluding any source from static scanning."""
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_PATHS:
        raise ReviewAuditError("Scoped tenant contracts require nonempty read scopes.")
    result = {}
    for scope in value:
        if not isinstance(scope, dict) or set(scope) != {"path", "reads"}:
            raise ReviewAuditError("Tenant scope requires exactly path and reads.")
        path = _relative_path(scope["path"]).as_posix()
        if path in result or not (workspace / path).is_file():
            raise ReviewAuditError(
                "Tenant scopes must name unique existing source files."
            )
        calls, bindings = _tenant_contract_entries(scope["reads"])
        calls = _tenant_contract_calls(calls)
        if not calls:
            raise ReviewAuditError("Scoped tenant read lists must be nonempty.")
        _tenant_scope_source(workspace, path, calls)
        result[path] = {
            "calls": calls,
            "bindings": _tenant_contract_bindings(bindings, calls),
        }
    return result


def _tenant_scope_source(workspace: Path, path: str, calls: tuple[str, ...]) -> None:
    """Reject stale or mistyped read declarations before producing a clean scan."""
    data, _evidence = _read(workspace, path)
    try:
        tree = ast.parse(data)
    except SyntaxError as exc:
        raise ReviewAuditError(
            "Tenant scope must name parseable Python source."
        ) from exc
    aliases = _module_security_aliases(tree)
    observed = {
        _normalized_call_name(node, aliases)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }
    if not set(calls).issubset(observed):
        raise ReviewAuditError("Tenant scope declares a read absent from its source.")


def _tenant_contract_entries(value: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Validate declared read rows before normalizing names and bindings."""
    if not isinstance(value, list) or len(value) > MAX_RULES:
        raise ReviewAuditError("Tenant-read contract requires a bounded reads list.")
    calls: list[str] = []
    bindings: list[str] = []
    for entry in value:
        if not isinstance(entry, dict) or set(entry) not in (
            {"call"},
            {"call", "binding"},
        ):
            raise ReviewAuditError(
                "Each tenant read requires call and optional binding."
            )
        call = entry["call"]
        if not isinstance(call, str):
            raise ReviewAuditError("Tenant read call must be a qualified Python name.")
        if call in calls:
            raise ReviewAuditError("Tenant-read contract calls must be unique.")
        calls.append(call)
        if "binding" in entry:
            if not isinstance(entry["binding"], str):
                raise ReviewAuditError("Tenant read binding must be a string.")
            bindings.append(f"{call}={entry['binding']}")
    return tuple(calls), tuple(bindings)


def _tenant_binding_entry(
    value: str, calls: tuple[str, ...], seen: set[str]
) -> tuple[str, str]:
    """Validate one declared call binding and return its normalized form."""
    if not isinstance(value, str) or value in seen:
        raise ReviewAuditError("Tenant read bindings must be unique strings.")
    seen.add(value)
    call, separator, binding = value.partition("=")
    if not separator or call not in calls or not NAME.fullmatch(call):
        raise ReviewAuditError(
            "Each tenant binding must name a declared qualified read call."
        )
    kind, selector, parameter = _tenant_binding_parts(binding)
    selector = _normalize_tenant_selector(kind, selector)
    return call, f"{kind}:{selector}:{parameter}"


def _tenant_binding_parts(binding: str) -> tuple[str, str, str]:
    parts = binding.split(":")
    if len(parts) != 3 or not NAME.fullmatch(parts[2]):
        raise ReviewAuditError(
            "Tenant bindings use call=position:INDEX:PARAMETER or "
            "call=keyword:NAME:PARAMETER."
        )
    return parts[0], parts[1], parts[2]


def _normalize_tenant_selector(kind: str, selector: str) -> str:
    if kind == "position":
        if not selector.isdecimal() or int(selector) > 255:
            raise ReviewAuditError("Tenant positional binding index must be 0-255.")
        return str(int(selector))
    if kind == "keyword":
        if not selector.isidentifier():
            raise ReviewAuditError("Tenant keyword binding must name an identifier.")
        return selector
    raise ReviewAuditError("Tenant binding kind must be position or keyword.")


def _tenant_comprehension_targets(function: ast.AST) -> set[int]:
    return {
        id(target)
        for statement in function.body
        for expression in _body_nodes(statement)
        if isinstance(
            expression,
            (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        )
        for generator in expression.generators
        for target in _body_nodes(generator.target)
        if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Store)
    }


def _tenant_discard_captures(statement: ast.stmt, names: set[str]) -> None:
    for child in _body_nodes(statement):
        if isinstance(child, (ast.MatchAs, ast.MatchStar)) and child.name:
            names.difference_update(
                name for name in tuple(names) if name.split(".")[0] == child.name
            )
        elif isinstance(child, ast.MatchMapping) and child.rest:
            names.discard(child.rest)
        elif isinstance(child, ast.ExceptHandler) and child.name:
            names.difference_update(
                name for name in tuple(names) if name.split(".")[0] == child.name
            )


def _tenant_discard_written_names(
    statement: ast.AST, names: set[str], comprehension_targets: set[int]
) -> None:
    for child in _body_nodes(statement):
        if (
            isinstance(child, ast.Name)
            and id(child) not in comprehension_targets
            and isinstance(child.ctx, (ast.Store, ast.Del))
        ):
            names.difference_update(
                name for name in tuple(names) if name.split(".")[0] == child.id
            )
        elif isinstance(child, (ast.Attribute, ast.Subscript)) and isinstance(
            child.ctx, (ast.Store, ast.Del)
        ):
            reference = (
                _tenant_reference(child.value)
                if isinstance(child, ast.Subscript)
                else _tenant_reference(child)
            )
            if any(
                name == reference or name.startswith(reference + ".") for name in names
            ):
                names.clear()


def _tenant_track_assignment(
    statement: ast.stmt, names: set[str], comprehension_targets: set[int]
) -> bool:
    target: ast.Name | None = None
    value: ast.expr | None = None
    if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
        candidate = statement.targets[0]
        if isinstance(candidate, ast.Name):
            target, value = candidate, statement.value
    elif isinstance(statement, ast.AnnAssign) and isinstance(
        statement.target, ast.Name
    ):
        target, value = statement.target, statement.value
    if target is None:
        return False
    reference = _tenant_reference(value)
    replacement = {
        target.id + name[len(reference) :]
        for name in names
        if reference and (name == reference or name.startswith(reference + "."))
    }
    names.difference_update(
        name
        for name in tuple(names)
        if name == target.id or name.startswith(target.id + ".")
    )
    if replacement:
        names.update(replacement)
    else:
        if value is not None:
            _tenant_discard_written_names(value, names, comprehension_targets)
    return True


def _tenant_reference(value: ast.AST | None) -> str:
    """Return only an explicit name/attribute chain; calls and indexing are unbound."""
    if isinstance(value, ast.Name):
        return value.id
    if isinstance(value, ast.Attribute):
        head = _tenant_reference(value.value)
        return f"{head}.{value.attr}" if head else ""
    return ""


def _tenant_discard_mutations(statement: ast.stmt, names: set[str]) -> None:
    """Invalidate explicit setattr/delattr writes to declared attribute scopes."""
    for node in _body_nodes(statement):
        if not isinstance(node, ast.Call) or _call_name(node) not in {
            "setattr",
            "delattr",
            "builtins.setattr",
            "builtins.delattr",
        }:
            continue
        if len(node.args) < 2 or not isinstance(node.args[1], ast.Constant):
            names.clear()
            continue
        reference = _tenant_reference(node.args[0])
        attribute = node.args[1].value
        if (
            isinstance(attribute, str)
            and reference
            and f"{reference}.{attribute}" in names
        ):
            names.clear()


def _tenant_bound_names(function: ast.AST, parameter: str, use: ast.Call) -> set[str]:
    """Track simple, unconditional tenant aliases and invalidate later writes."""
    names = {parameter}
    comprehension_targets = _tenant_comprehension_targets(function)
    for statement in function.body:
        if (statement.lineno, statement.col_offset) >= (use.lineno, use.col_offset):
            break
        _tenant_discard_captures(statement, names)
        _tenant_discard_mutations(statement, names)
        if _tenant_track_assignment(statement, names, comprehension_targets):
            continue
        _tenant_discard_written_names(statement, names, comprehension_targets)
    return names


def _tenant_argument_bound(
    node: ast.Call,
    function: ast.AST,
    parameters: set[str],
    bindings: tuple[str, ...],
) -> bool:
    if not bindings:
        value = next(
            (item.value for item in node.keywords if item.arg == "tenant_id"), None
        )
        return (
            isinstance(value, ast.Name)
            and "tenant_id" in parameters
            and value.id in _tenant_bound_names(function, "tenant_id", node)
        )
    for binding in bindings:
        kind, selector, parameter = binding.split(":", 2)
        value = (
            next((item.value for item in node.keywords if item.arg == selector), None)
            if kind == "keyword"
            else node.args[int(selector)]
            if int(selector) < len(node.args)
            and not any(
                isinstance(item, ast.Starred) for item in node.args[: int(selector)]
            )
            else None
        )
        if (
            _tenant_reference(value) in _tenant_bound_names(function, parameter, node)
            and parameter.split(".")[0] in parameters
        ):
            return True
    return False


def _orm_read_candidates(
    nodes: list[ast.AST], aliases: dict[str, str]
) -> list[tuple[str, ast.Call]]:
    modules = {
        node.module
        for node in nodes
        if isinstance(node, ast.ImportFrom) and node.module
    }
    modules.update(
        item.name
        for node in nodes
        if isinstance(node, ast.Import)
        for item in node.names
    )
    sql_orm = any(module.startswith(("sqlalchemy", "sqlmodel")) for module in modules)
    django_orm = any(module.startswith("django.db.models") for module in modules)
    other_orm = any(module.startswith(("peewee", "tortoise")) for module in modules)
    candidates = []
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        name = _normalized_call_name(node, aliases)
        leaf = name.rsplit(".", 1)[-1]
        manager_read = ".objects." in f".{name}." and leaf in {
            "all",
            "aggregate",
            "dates",
            "datetimes",
            "earliest",
            "exclude",
            "filter",
            "filter_by",
            "get",
            "get_or_create",
            "first",
            "in_bulk",
            "iterator",
            "latest",
            "one",
            "order_by",
            "raw",
            "reverse",
            "select_related",
            "update_or_create",
            "values",
            "values_list",
            "exists",
            "count",
        }
        orm_query = (
            (
                sql_orm
                and leaf
                in {"query", "execute", "exec", "scalars", "scalar", "select", "get"}
            )
            or (
                other_orm
                and leaf
                in {
                    "select",
                    "filter",
                    "filter_by",
                    "get",
                    "get_or_none",
                    "exclude",
                    "first",
                    "all",
                    "exists",
                    "count",
                    "fetch",
                }
            )
            or (
                django_orm
                and leaf
                in {
                    "get",
                    "filter",
                    "exclude",
                    "all",
                    "first",
                    "last",
                    "exists",
                    "count",
                    "values",
                    "values_list",
                    "iterator",
                    "get_or_create",
                    "update_or_create",
                    "latest",
                    "earliest",
                    "in_bulk",
                    "raw",
                }
            )
        )
        if manager_read or orm_query:
            candidates.append((name, node))
    return candidates


def _tenant_function_findings(
    relative: str,
    function: ast.AST,
    calls: tuple[str, ...],
    aliases: dict,
    bindings: dict[str, tuple[str, ...]],
) -> list[dict]:
    findings = []
    positional = [*function.args.posonlyargs, *function.args.args]
    required_positional = positional[: len(positional) - len(function.args.defaults)]
    parameters = {argument.arg for argument in required_positional}
    parameters.update(
        argument.arg
        for argument, default in zip(
            function.args.kwonlyargs, function.args.kw_defaults
        )
        if default is None
    )
    nodes = (n for statement in function.body for n in _body_nodes(statement))
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        call = _normalized_call_name(node, aliases)
        if call in calls and not _tenant_argument_bound(
            node, function, parameters, bindings.get(call, ())
        ):
            findings.append(
                _security_finding(
                    "SECURITY_MISSING_TENANT_ISOLATION",
                    relative,
                    node,
                    (
                        f"Declared tenant read {call} lacks its configured argument "
                        "bound to the declared function parameter. Configure "
                        f"--tenant-read-binding {call}=position:INDEX:PARAMETER or "
                        f"{call}=keyword:NAME:PARAMETER, then independently challenge "
                        "cross-tenant access; this static check does not authenticate identity."
                    ),
                    "HIGH",
                    call=call,
                    symbol=function.name,
                )
            )
    return findings


def _tenant_read_findings(
    relative: str,
    nodes: list[ast.AST],
    calls: tuple[str, ...],
    aliases: dict[str, str],
    bindings: dict[str, tuple[str, ...]],
) -> list[dict]:
    if not calls:
        return []
    return [
        finding
        for function in nodes
        if isinstance(function, _FUNCTION_NODES)
        for finding in _tenant_function_findings(
            relative, function, calls, aliases, bindings
        )
    ]


def _test_oracle_findings(
    relative: str,
    nodes: list[ast.AST],
    aliases: dict[str, str],
    helper_names: set[str],
    unittest_methods: set[int],
    class_helpers: dict[int, set[str]] | None = None,
    weak_helper_names: set[str] | None = None,
    click_runners: set[str] | None = None,
    ty_assert_type: bool = False,
    test_file_patterns: set[str] | None = None,
    inherited_pytest_methods: set[int] | None = None,
    flask_apps: set[str] | None = None,
    callback_invokers: dict | None = None,
    oracle_context: dict | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    parents = _oracle_ancestor_map(nodes[0].body)
    from .review_integrity import test_execution_findings

    for node in nodes:
        if not isinstance(node, _FUNCTION_NODES) or any(
            isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
            for parent, _child in parents.get(id(node), ())
        ):
            continue
        if not _collected_test_function(
            relative,
            node,
            parents,
            unittest_methods,
            aliases,
            test_file_patterns
            if test_file_patterns is not None
            else set(_TEST_FILE_PATTERNS),
            inherited_pytest_methods or set(),
            nodes,
        ):
            continue
        results, shadowed = test_execution_findings(node, relative, parents, nodes[0])
        findings.extend(results)
        if shadowed:
            continue
        if id(node) not in unittest_methods and _empty_test_parameters(node, aliases):
            findings.append(
                _security_finding(
                    "QUALITY_EMPTY_PARAMETER_SET",
                    relative,
                    node,
                    "Explicit empty pytest parameters collect no executable cases; supply cases or record this gap.",
                    "INFO",
                    symbol=node.name,
                    state="INCOMPLETE",
                )
            )
            continue
        node._oracle_click_runners = click_runners or set()
        node._oracle_module = nodes[0]
        findings.extend(integrity.discarded_assertion_error_findings(relative, node))
        node._oracle_async_functions = {
            item.name
            for item in [*nodes[0].body, *node.body]
            if isinstance(item, ast.AsyncFunctionDef)
        }
        is_unittest_method = id(node) in unittest_methods
        scoped_aliases = _scope_security_aliases(aliases, node)
        helpers = helper_names | (class_helpers or {}).get(id(node), set())
        helpers |= _invoked_nested_assertion_helpers(node, aliases, helpers)
        if ty_assert_type:
            helpers |= _ty_assertion_helpers(node, scoped_aliases)
        hollow_helpers = helpers | (weak_helper_names or set())
        if _proven_dispatch_assertion(
            node, scoped_aliases, helpers, flask_apps or set(), callback_invokers or {}
        ):
            continue
        hollow = _hollow_test_finding(
            relative,
            node,
            scoped_aliases,
            hollow_helpers,
            unittest_context=is_unittest_method,
            oracle_context=oracle_context,
        )
        weak = _weak_test_oracle_finding(
            relative,
            node,
            scoped_aliases,
            helpers,
            unittest_context=is_unittest_method,
            weak_helper_names=weak_helper_names,
        )
        if hollow is not None and not (
            weak is not None and hollow["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
        ):
            findings.append(hollow)
        if weak is not None:
            findings.append(weak)
    return findings


def _collected_test_function(
    relative,
    node,
    parents,
    unittest_methods,
    aliases,
    test_file_patterns,
    inherited_pytest_methods,
    nodes,
):
    """Match pytest/unittest collection context instead of function spelling alone."""
    path = Path(relative)
    pytest_file = any(fnmatchcase(path.name, pattern) for pattern in test_file_patterns)
    unittest_file = path.name.startswith("test") and path.name.endswith(".py")
    if not node.name.startswith("test_"):
        return False
    inherited = id(node) in inherited_pytest_methods
    if (
        not inherited
        and not pytest_file
        and not (unittest_file and id(node) in unittest_methods)
    ):
        return False
    if any(
        _resolved_ast_name(
            decorator.func if isinstance(decorator, ast.Call) else decorator,
            aliases,
        )
        == "pytest.fixture"
        for decorator in node.decorator_list
    ):
        return False
    if inherited:
        return True
    enclosing = [
        parent
        for parent, _child in parents.get(id(node), ())
        if isinstance(parent, ast.ClassDef)
    ]
    if not enclosing:
        return pytest_file
    if unittest_file and id(node) in unittest_methods:
        return True
    cls = enclosing[-1]
    return pytest_file and (
        _pytest_collects_class(cls, parents)
        or _pytest_inherited_by_collected_class(cls, nodes)
    )


def _pytest_collects_class(cls, parents):
    if not cls.name.startswith("Test") or any(
        isinstance(member, _FUNCTION_NODES) and member.name == "__init__"
        for member in cls.body
    ):
        return False
    enclosing = [
        parent
        for parent, _child in parents.get(id(cls), ())
        if isinstance(parent, ast.ClassDef)
    ]
    return not enclosing or _pytest_collects_class(enclosing[-1], parents)


def _pytest_inherited_by_collected_class(base, nodes):
    classes = {node.name: node for node in nodes if isinstance(node, ast.ClassDef)}
    for child in classes.values():
        if not child.name.startswith("Test") or any(
            isinstance(member, _FUNCTION_NODES) and member.name == "__init__"
            for member in child.body
        ):
            continue
        if _pytest_class_inherits(child, base.name, classes, set()):
            return True
    return False


def _pytest_class_inherits(cls, target, classes, seen):
    if cls.name in seen:
        return False
    seen.add(cls.name)
    for parent in cls.bases:
        name = _name(parent).rsplit(".", 1)[-1]
        if name == target or (
            name in classes
            and _pytest_class_inherits(classes[name], target, classes, seen)
        ):
            return True
    return False


_TEST_FILE_PATTERNS = ("test_*.py", "*_test.py")
_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


def _pytest_collection_config(root):
    """Read pytest selected root config; malformed config is incomplete."""
    defaults = set(_TEST_FILE_PATTERNS)
    candidates = (
        ("pytest.toml", "toml-pytest"),
        (".pytest.toml", "toml-pytest"),
        ("pytest.ini", "pytest"),
        (".pytest.ini", "pytest"),
        ("pyproject.toml", "pyproject"),
        ("tox.ini", "pytest"),
        ("setup.cfg", "tool:pytest"),
    )
    for relative, section in candidates:
        result = _pytest_config_file(root, relative, section, defaults)
        if result is not None and result[1].get("state") != "absent-section":
            if result[1].get("state") in {
                "invalid",
                "oversized",
                "unreadable",
                "unsupported",
            }:
                raise ReviewAuditError(
                    f"Cannot determine pytest test collection from {relative}: "
                    f"{result[1]['state']} configuration."
                )
            return result
    return defaults, {"path": None, "state": "missing"}


def _pytest_config_file(root, relative, section, defaults):
    try:
        path = local_file(root, relative)
        size = path.stat().st_size
        if size > MAX_BYTES:
            return set(), {"path": relative, "state": "oversized", "bytes": size}
        data = path.read_bytes()
    except RuntimeAuditError as exc:
        if exc.code == "E_SOURCE_MISSING":
            return None
        return set(), {"path": relative, "state": "unreadable"}
    except OSError:
        return set(), {"path": relative, "state": "unreadable"}
    return _pytest_config_data(data, relative, section, defaults)


def _pytest_config_data(data, relative, section, defaults):
    identity = {
        "path": relative,
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
        "state": "read",
    }
    if len(data) > MAX_BYTES:
        return set(), {**identity, "state": "oversized"}
    try:
        text = data.decode("utf-8")
        configured = _pytest_pattern_value(text, section)
    except (UnicodeError, ValueError, configparser.Error):
        return set(), {**identity, "state": "invalid"}
    if configured is _INVALID_PYTEST_CONFIG:
        return set(), {**identity, "state": "invalid"}
    if configured is _UNSUPPORTED_PYTEST_CONFIG:
        return defaults, {**identity, "state": "unsupported"}
    if configured is _ABSENT_PYTEST_SECTION:
        if relative in {"pytest.toml", ".pytest.toml", "pytest.ini", ".pytest.ini"}:
            return defaults, identity
        return defaults, {**identity, "state": "absent-section"}
    patterns = set(defaults)
    if configured is not None:
        patterns = set(configured)
    return patterns, identity


def _pytest_pattern_value(text, section):
    if section in {"pyproject", "toml-pytest"}:
        return _toml_pytest_pattern_value(text, section)
    parser = configparser.ConfigParser()
    parser.read_string(text)
    if section not in parser:
        return _ABSENT_PYTEST_SECTION
    options = dict(parser.items(section))
    if not _supported_pytest_function_patterns(options):
        return _UNSUPPORTED_PYTEST_CONFIG
    value = parser.get(section, "python_files", fallback=None)
    return value.split() if value is not None else None


def _toml_pytest_pattern_value(text, section):
    document = tomllib.loads(text)
    pytest = (
        document.get("pytest")
        if section == "toml-pytest"
        else document.get("tool", {}).get("pytest")
    )
    if pytest is None:
        return _ABSENT_PYTEST_SECTION
    options = pytest.get("ini_options", pytest)
    if not isinstance(options, dict):
        return _INVALID_PYTEST_CONFIG
    if not _supported_pytest_function_patterns(options):
        return _UNSUPPORTED_PYTEST_CONFIG
    value = options.get("python_files")
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return None if "python_files" not in options else _INVALID_PYTEST_CONFIG


def _supported_pytest_function_patterns(options):
    functions = options.get("python_functions")
    classes = options.get("python_classes")
    if functions is not None and _pytest_pattern_list(functions) != ["test_*"]:
        return False
    if classes is not None and _pytest_pattern_list(classes) != ["Test*"]:
        return False
    return True


def _pytest_pattern_list(value):
    return value.split() if isinstance(value, str) else value


_ABSENT_PYTEST_SECTION = object()
_INVALID_PYTEST_CONFIG = object()
_UNSUPPORTED_PYTEST_CONFIG = object()


def _security_node_findings(
    relative: str,
    node: ast.AST,
    aliases: dict[str, str],
    roundtrip_aliases: dict | None = None,
) -> list[dict[str, Any]]:
    if isinstance(node, ast.Call):
        node._security_configuration_aliases = aliases
        call = integrity.security_call_name(node, aliases)
        finding = _security_call_finding(call, relative, node)
        if finding and finding["code"] == "SECURITY_UNSAFE_DESERIALIZATION":
            if _test_serialization_roundtrip(relative, node, roundtrip_aliases or {}):
                finding["severity"] = "INFO"
                finding["message"] = (
                    "Test deserializes bytes produced by a direct local serialization. "
                    "This is not external-byte input; custom object reducers still execute code."
                )
                finding["facts"]["input_provenance"] = "direct_local_serialization"
        return [finding] if finding is not None else []
    if isinstance(node, ast.ExceptHandler):
        finding = _bare_except_finding(relative, node)
        return [finding] if finding is not None else []
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        return integrity.security_assignment_findings(relative, node, aliases)
    return []


def _test_serialization_roundtrip(relative: str, node: ast.Call, aliases: dict) -> bool:
    from .context_efficiency import _test_serialization_roundtrip as check

    return check(relative, node, aliases)


def _unmodified_serialization_aliases(nodes: list[ast.AST], aliases: dict) -> dict:
    """Only downgrade round-trips through imports without source-visible mutation."""
    mutated = {
        _name(node).split(".", 1)[0]
        for node in nodes
        if isinstance(node, (ast.Name, ast.Attribute))
        and isinstance(node.ctx, (ast.Store, ast.Del))
    }
    mutated.update(node.arg for node in nodes if isinstance(node, ast.arg))
    for node in nodes:
        if not isinstance(node, ast.Call) or not node.args:
            continue
        if _call_name(node).rsplit(".", 1)[-1] in {
            "setattr",
            "delattr",
            "object",
            "patch",
            "dict",
        }:
            target = node.args[0]
            name = (
                target.value
                if isinstance(target, ast.Constant) and isinstance(target.value, str)
                else _name(target)
            )
            mutated.add(name.split(".", 1)[0])
    return {
        name: value
        for name, value in aliases.items()
        if name not in mutated and value.split(".", 1)[0] not in mutated
    }


def _security_scan_tree(
    root: Path,
    path: Path,
    tree: ast.AST,
    tenant_read_calls: tuple[str, ...] = (),
    tenant_read_bindings: dict[str, tuple[str, ...]] | None = None,
    oracle_context: dict | None = None,
    test_file_patterns: set[str] | None = None,
    tenant_policy_applies: bool = False,
) -> list[dict[str, Any]]:
    relative = path.relative_to(root).as_posix()
    tree._security_source_context = (oracle_context or {}).get(
        "_security_source_context"
    )
    tree._fixed_program_workspace = (oracle_context or {}).get(
        "fixed_program_workspace", {}
    )
    nodes = list(ast.walk(tree))
    aliases = _security_aliases(nodes)
    for node in nodes:
        node._scan_bound_names = None
        node._oracle_layout = None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            node._oracle_module = tree
    source_sink_findings = integrity.security_source_sink_findings(
        relative, tree, nodes, aliases
    )
    oracle_aliases = _scope_security_aliases(_module_security_aliases(tree), tree)
    context = oracle_context or {}
    tree._oracle_async_runner_fixtures = context.get("async_runner_fixtures", {})
    tree._oracle_mock_fixture_provenance = context.get("mock_fixture_provenance", {})
    helper_names = _local_assertion_helpers(tree, oracle_aliases) | set(
        context.get("helpers", ())
    )
    weak_helper_names = _local_weak_assertion_helpers(tree, oracle_aliases) | set(
        context.get("weak_helpers", ())
    )
    unittest_methods = _unittest_test_methods(tree, oracle_aliases)
    for cls in tree.body:
        if isinstance(cls, ast.ClassDef) and cls.name in context.get("mixins", ()):
            unittest_methods.update(id(method) for method in cls.body)
    class_helpers = _class_oracle_helpers(tree, oracle_aliases, unittest_methods)
    from .review_integrity import redirect_source_findings
    from .semantic_credential_sensor import (
        configuration_and_credential_findings as configuration_findings,
    )

    findings = _tenant_read_findings(
        relative, nodes, tenant_read_calls, aliases, tenant_read_bindings or {}
    )
    from .context_efficiency import _undeclared_tenant_read_findings

    findings.extend(
        _undeclared_tenant_read_findings(
            relative,
            nodes,
            aliases,
            set(tenant_read_calls),
            tenant_policy_applies,
        )
    )
    findings.extend(source_sink_findings)
    findings.extend(
        _test_oracle_findings(
            relative,
            nodes,
            oracle_aliases,
            helper_names,
            unittest_methods,
            class_helpers,
            weak_helper_names,
            context.get("click_runners", set()),
            context.get("typecheck", False),
            test_file_patterns,
            _pytest_inherited_method_ids(tree, context.get("pytest_inherited", set())),
            context.get("flask_apps", set()),
            context.get("callback_invokers", {}),
            context,
        )
    )
    roundtrip_aliases = _unmodified_serialization_aliases(nodes, aliases)
    for node in nodes:
        findings.extend(
            _security_node_findings(relative, node, aliases, roundtrip_aliases)
        )
    findings.extend(configuration_findings(tree, aliases, relative))
    findings.extend(redirect_source_findings(relative, tree, aliases, nodes))
    return findings


def _security_source_bytes(workspace: Path, relative: str) -> bytes:
    """Read a bounded regular source without following linked workspace entries."""
    from .context_efficiency import _read_bounded_workspace_source

    return _read_bounded_workspace_source(workspace, relative, MAX_BYTES, local_file)


def _security_scan_file(
    workspace: Path,
    path: Path,
    tenant_read_calls: tuple[str, ...] = (),
    tenant_read_bindings: dict[str, tuple[str, ...]] | None = None,
    oracle_context: dict | None = None,
    test_file_patterns: set[str] | None = None,
    source_data: bytes | None = None,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], str]:
    """Scan one bounded Python source and return its byte binding and findings."""
    from .context_efficiency import _scan_security_source

    return _scan_security_source(
        workspace,
        path,
        tenant_read_calls,
        tenant_read_bindings,
        oracle_context,
        test_file_patterns,
        source_data,
    )


def _security_scan_file_snapshot(
    workspace,
    path,
    calls,
    call_bindings,
    context,
    patterns,
    source_data,
    tree,
    fingerprint,
):
    """Scan one producer-owned tree after matching its bytes and structure."""
    from .context_efficiency import _scan_security_source

    return _scan_security_source(
        workspace,
        path,
        calls,
        call_bindings,
        context,
        patterns,
        source_data,
        tree,
        fingerprint,
    )


def _oracle_tree_fingerprint(tree):
    """Hash AST structure and source locations without considering sidecars."""
    return sha256(ast.dump(tree, include_attributes=True).encode("utf-8")).hexdigest()


def _verify_security_bindings(workspace: Path, bindings: list[dict[str, Any]]) -> None:
    """Reject a source that changes after its scan but before receipt creation."""
    from .context_efficiency import _verify_source_bindings

    return _verify_source_bindings(
        workspace,
        bindings,
        _security_source_bytes,
        MAX_BYTES,
        lambda data: _measure_hash("source_hash", sha256, data),
        ReviewAuditError,
        RuntimeAuditError,
        "security scan",
    )


def _blocked_security_scan_report(
    workspace: Path,
    files: list[Path],
    tenant_read_calls: tuple[str, ...],
    tenant_read_bindings: dict[str, tuple[str, ...]],
    tenant_policy_applies: bool = False,
) -> dict[str, Any]:
    """Return a fail-closed receipt when the bounded inventory is exceeded."""
    relative_paths = [path.relative_to(workspace).as_posix() for path in files]
    finding = _security_finding(
        "SECURITY_AUDIT_INCOMPLETE",
        ".",
        ast.Module(body=[], type_ignores=[]),
        (
            f"Eligible Python source inventory contains {len(files)} files, above "
            f"the {MAX_SECURITY_SOURCE_FILES}-file scan limit. No files were "
            "scanned; partition the workspace or use a reviewed larger limit."
        ),
        "HIGH",
        files_discovered=len(files),
        files_scanned=0,
    )
    core = {
        "schema": SECURITY_SCHEMA,
        "marker": "SECURITY_AUDIT_COMPLETE",
        "state": "BLOCKED",
        "files_scanned": 0,
        "parse_errors": 0,
        "unreadable_sources": 0,
        "oversized_sources": 0,
        "audit_coverage": {
            "language": "Python",
            "files_discovered": len(files),
            "files_attempted": 0,
            "files_audited": 0,
            "audit_rate": 0.0,
            "rate_defined": True,
            "measurement_state": "blocked",
            "inventory_complete": True,
            "complete": False,
            "limit": MAX_SECURITY_SOURCE_FILES,
            "inventory_sha256": sha256(
                "\n".join(relative_paths).encode("utf-8")
            ).hexdigest(),
        },
        "tenant_read_contract": _tenant_read_contract(
            tenant_read_calls, tenant_read_bindings, tenant_policy_applies
        ),
        "sources": [],
        "oracle_context": {
            "mode": "not_assessed_source_limit",
            "configuration_sources": [],
        },
        "findings": [finding],
        "finding_counts": {finding["code"]: 1},
        "governance": "human_controlled",
        "authority": {
            "execution": False,
            "approval": False,
            "publication": False,
            "deployment": False,
        },
        "claim_boundary": (
            "No security analysis completed because the eligible Python source "
            "inventory exceeded the configured scan limit. Other languages, "
            "runtime behavior, dependency advisories, and release approval are "
            "outside this scanner's scope."
        ),
        "action_summary": finding["message"],
    }
    return _seal_security_scan(core)


def _tenant_read_contract(
    tenant_read_calls: tuple[str, ...],
    tenant_read_bindings: dict[str, tuple[str, ...]],
    tenant_policy_applies: bool = False,
) -> dict[str, Any]:
    return {
        "calls": list(tenant_read_calls),
        "policy_applies": tenant_policy_applies,
        "keyword": "tenant_id",
        "legacy_binding": "keyword:tenant_id:tenant_id",
        "argument_bindings": {
            call: list(bindings) for call, bindings in tenant_read_bindings.items()
        },
        "identity_authentication_proven": False,
    }


def _security_scan_database_context(
    workspace, source_bytes, python_inventory, projection
):
    """Use a cold owned projection or parse normally when no projection was produced."""
    if projection:
        return projection
    from .context_efficiency import database_workspace_context

    return database_workspace_context(
        workspace, source_bytes, _security_source_bytes, python_inventory
    )


def _scan_security_sources(
    workspace: Path,
    files: list[Path],
    tenant_read_calls: tuple[str, ...],
    tenant_read_bindings: dict[str, tuple[str, ...]],
    scoped_reads: dict | None = None,
    *,
    cache_enabled: bool = True,
    test_file_patterns: set[str] | None = None,
    database_context: dict | None = None,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, int],
    dict[str, int],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    findings: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    outcomes = {"syntax_error": 0, "unreadable": 0, "too_large": 0, "audited": 0}
    if test_file_patterns is None:
        test_file_patterns, collection_identity = _pytest_collection_config(workspace)
    else:
        collection_identity = {
            "state": "supplied",
            "patterns": sorted(test_file_patterns),
        }
    if collection_identity.get("state") in {
        "invalid",
        "oversized",
        "unreadable",
        "unsupported",
    }:
        findings.append(
            _security_finding(
                "QUALITY_TEST_COLLECTION_CONFIG_INCOMPLETE",
                collection_identity.get("path") or "pytest configuration",
                ast.Module(),
                "Pytest collection configuration could not be fully interpreted; hollow-test coverage is incomplete.",
                "INFO",
                state=collection_identity["state"],
            )
        )
    python_inventory = []
    database_projection = {}
    snapshot_rows = {}

    def consume_security_snapshots(snapshots, fingerprints, contexts, retained):
        """Run the fixed scanner closure while its producer-owned trees are live."""
        from .context_efficiency import _consume_security_snapshots

        snapshot_rows.update(
            _consume_security_snapshots(
                workspace,
                files,
                snapshots,
                fingerprints,
                contexts,
                retained,
                scoped_reads,
                tenant_read_calls,
                tenant_read_bindings,
                test_file_patterns,
                _security_scan_file_snapshot,
            )
        )

    contexts, context_bindings, oracle_edges, source_bytes = _project_oracle_context(
        workspace,
        files,
        cache_enabled=cache_enabled,
        collection_identity=collection_identity,
        python_inventory_out=python_inventory,
        database_context_out=database_projection,
        security_snapshot_consumer=consume_security_snapshots,
    )
    from .context_efficiency import (
        _scan_missing_security_snapshot,
        verify_database_context,
    )

    database = _security_scan_database_context(
        workspace, source_bytes, python_inventory, database_projection
    )
    context_bindings.extend(database.pop("_bindings"))
    if database_context is not None:
        database_context.update(database)
    for path in files:
        scanned = _scan_missing_security_snapshot(
            snapshot_rows.pop(path, None),
            workspace,
            path,
            scoped_reads,
            tenant_read_calls,
            tenant_read_bindings,
            contexts,
            source_bytes,
            test_file_patterns,
            _security_scan_file,
        )
        binding, file_findings, outcome = scanned
        if binding is not None:
            bindings.append(binding)
        findings.extend(file_findings)
        if outcome in outcomes:
            outcomes[outcome] += 1
    _verify_security_bindings(workspace, context_bindings + bindings)
    verify_database_context(workspace, database, ReviewAuditError)
    findings.sort(
        key=lambda item: (item["path"], item["line"], item["code"], item["column"])
    )
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["code"]] = counts.get(finding["code"], 0) + 1
    scanned = {item["path"] for item in bindings}
    extra_bindings = [item for item in context_bindings if item["path"] not in scanned]
    return bindings, findings, counts, outcomes, oracle_edges, extra_bindings


def _seal_security_scan(core: dict[str, Any]) -> dict[str, Any]:
    integrity.partition_proven_primitive_observations(core)
    candidate = sha256(
        json.dumps(
            _security_scan_report_candidate_payload(core),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    core["candidate_sha256"] = candidate
    core["agent_actions"] = [
        audit_remediation_packet(candidate, item) for item in core["findings"]
    ]
    core.pop("audit_sha256", None)
    core["audit_sha256"] = sha256(
        json.dumps(
            core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    return core


def _security_scan_report(
    files: list[Path],
    findings: list[dict[str, Any]],
    bindings: list[dict[str, Any]],
    counts: dict[str, int],
    outcomes: dict[str, int],
    tenant_read_calls: tuple[str, ...],
    tenant_read_bindings: dict[str, tuple[str, ...]],
    oracle_edges: list[dict[str, Any]],
    oracle_configuration: list[dict[str, Any]],
    database_context: dict | None = None,
    tenant_policy_applies: bool = False,
) -> dict[str, Any]:
    audit_coverage = _security_scan_coverage(files, outcomes, MAX_SECURITY_SOURCE_FILES)
    state = _security_scan_state(files, findings, database_context, audit_coverage)
    core: dict[str, Any] = {
        "schema": SECURITY_SCHEMA,
        "marker": "SECURITY_AUDIT_COMPLETE",
        "state": state,
        "files_scanned": len(bindings),
        "parse_errors": outcomes["syntax_error"],
        "unreadable_sources": outcomes["unreadable"],
        "oversized_sources": outcomes["too_large"],
        "audit_coverage": audit_coverage,
        "tenant_read_contract": _tenant_read_contract(
            tenant_read_calls, tenant_read_bindings, tenant_policy_applies
        ),
        "oracle_context": contracts.import_context_metadata(
            files, oracle_edges, oracle_configuration
        ),
        "sources": bindings,
        "database_context": database_context or {},
        "findings": findings,
        "finding_counts": dict(sorted(counts.items())),
        "governance": "human_controlled",
        "authority": {
            "execution": False,
            "approval": False,
            "publication": False,
            "deployment": False,
        },
        "claim_boundary": "Bounded Python AST pattern scan only. Declared tenant argument bindings verify syntactic pass-through, not tenant identity, authorization, or access isolation; this is not a penetration test, runtime exploit proof, dependency advisory, or release approval.",
    }
    core["source_manifest_sha256"] = sha256(
        json.dumps(
            {
                "sources": bindings,
                "oracle_context": core["oracle_context"],
                "database_context": core["database_context"],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    core["action_summary"] = _security_scan_action_summary(state)
    return _seal_security_scan(core)


def _oracle_bound_row(workspace: Path, row: dict, sources: dict) -> None:
    """Require both original test and mutated production source in this scan."""
    for path, digest in (
        (row["path"], row["test_sha256"]),
        (row["mutation"]["source_path"], row["mutation"]["source_sha256"]),
    ):
        if sources.get(path) != digest:
            raise ReviewAuditError(
                "Runtime oracle source binding does not match this scan."
            )
    raw = _security_source_bytes(workspace, row["path"])
    if len(raw) > MAX_BYTES or sha256(raw).hexdigest() != row["test_sha256"]:
        raise ReviewAuditError(
            "Runtime oracle test source changed during reconciliation."
        )
    tree = ast.parse(raw, filename=row["path"])
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, _FUNCTION_NODES)
        and node.name == row["symbol"]
        and node.lineno == row["line"]
    ]
    if len(matches) != 1:
        raise ReviewAuditError("Runtime oracle test identity does not match this scan.")
    parents = _oracle_ancestor_map(tree.body).get(id(matches[0]), ())
    classes = [
        parent.name for parent, _child in parents if isinstance(parent, ast.ClassDef)
    ]
    if any(isinstance(parent, _FUNCTION_NODES) for parent, _child in parents):
        raise ReviewAuditError(
            "Runtime oracle cannot credit a nested helper as a collected test."
        )
    prefix = "::".join([row["path"], *classes, row["symbol"]])
    if any(
        case != prefix and not case.startswith(prefix + "[")
        for case in row["baseline"]["case_ids"]
    ):
        raise ReviewAuditError(
            "Runtime oracle collected node does not match the qualified test."
        )


def _reconcile_runtime_oracles(workspace: Path, core: dict, evidence: tuple) -> dict:
    """Credit only signed same-test mutation observations, keeping static history."""
    from .runtime_attestation import RuntimeAttestationError, verify_signed_test_oracles

    receipt, trust_root, trust_sha256, environment_sha256 = evidence
    if not all(value is not None for value in evidence):
        raise ReviewAuditError(
            "Runtime oracle evidence requires receipt, trust root and both pins."
        )
    if not core["audit_coverage"]["complete"]:
        raise ReviewAuditError(
            "Runtime oracle reconciliation requires a complete source scan."
        )
    try:
        verified = verify_signed_test_oracles(
            local_file(workspace, receipt),
            local_file(workspace, trust_root),
            trust_root_sha256=trust_sha256,
            source_manifest_sha256=core["source_manifest_sha256"],
            environment_sha256=environment_sha256,
        )
        sources = {item["path"]: item["sha256"] for item in core["sources"]}
        schema = verified.get("schema", "")
        manifests = {}
        for row in verified["tests"]:
            _oracle_bound_row(workspace, row, sources)
            manifests[id(row)] = runtime_config_sources(workspace, core, row, schema)
        bindings = core["sources"] + core["oracle_context"]["configuration_sources"]
        _verify_security_bindings(workspace, bindings)
    except (RuntimeAttestationError, RuntimeAuditError, OSError, ValueError) as error:
        raise ReviewAuditError(
            "Runtime oracle evidence rejected: " + type(error).__name__
        ) from error
    rows = {(row["path"], row["line"], row["symbol"]): row for row in verified["tests"]}
    from .review_integrity import runtime_finding_coverage

    retained, reconciled = [], []

    for finding in core["findings"]:
        key = (finding["path"], finding["line"], finding["facts"].get("symbol"))
        row = rows.get(key)
        arguments = (workspace, finding, row, verified.get("schema", ""))
        config_manifest = manifests.get(id(row), []) if row is not None else []
        if runtime_finding_coverage(*arguments, config_manifest):
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
    core["state"] = _security_scan_state(
        core["sources"], retained, coverage=core.get("audit_coverage")
    )
    core["action_summary"] = _security_scan_action_summary(core["state"])
    return _seal_security_scan(core)


def _validate_tenant_scopes(workspace: Path, scopes: dict | None) -> dict:
    """Revalidate programmatic declarations through the same contract boundary."""
    if scopes is None:
        return {}
    if not isinstance(scopes, dict) or len(scopes) > MAX_PATHS:
        raise ReviewAuditError("Invalid tenant read scope map.")
    rows = []
    for path, scope in scopes.items():
        if not isinstance(scope, dict) or set(scope) != {"calls", "bindings"}:
            raise ReviewAuditError("Invalid scoped tenant calls and bindings.")
        if not isinstance(scope["calls"], (tuple, list)):
            raise ReviewAuditError("Scoped calls must be a bounded sequence.")
        calls = _tenant_contract_calls(tuple(scope["calls"]))
        bindings = scope["bindings"]
        if not isinstance(bindings, dict) or set(bindings) - set(calls):
            raise ReviewAuditError("Scoped bindings must name declared calls.")
        reads = [_tenant_scope_read(call, bindings) for call in calls]
        rows.append({"path": path, "reads": reads})
    return _tenant_scoped_entries(workspace, rows) if rows else {}


def _validate_cache_enabled(value: bool) -> bool:
    if not isinstance(value, bool):
        raise ReviewAuditError("cache_enabled must be a boolean.")
    return value


def _tenant_scope_read(call: str, bindings: dict) -> dict:
    values = bindings.get(call, ())
    if not isinstance(values, (tuple, list)) or len(values) > 1:
        raise ReviewAuditError("Each scoped call requires at most one binding.")
    return {"call": call, "binding": values[0]} if values else {"call": call}


def security_scan(
    root: Path,
    *,
    tenant_read_calls: tuple[str, ...] = (),
    tenant_read_bindings: tuple[str, ...] = (),
    tenant_read_scopes: dict | None = None,
    tenant_policy_applies: bool = False,
    cache_enabled: bool = True,
    oracle_evidence: str | None = None,
    oracle_trust_root: str | None = None,
    oracle_trust_sha256: str | None = None,
    oracle_environment_sha256: str | None = None,
) -> dict[str, Any]:
    """Run a bounded AST scan with content-bound process-local context reuse."""
    workspace = Path(root).resolve()
    if not isinstance(tenant_policy_applies, bool):
        raise ReviewAuditError("tenant_policy_applies must be a boolean.")
    tenant_read_calls = _tenant_contract_calls(tenant_read_calls)
    tenant_read_bindings = _tenant_contract_bindings(
        tenant_read_bindings, tenant_read_calls
    )
    tenant_read_scopes = _validate_tenant_scopes(workspace, tenant_read_scopes)
    cache_enabled = _validate_cache_enabled(cache_enabled)
    evidence = (
        oracle_evidence,
        oracle_trust_root,
        oracle_trust_sha256,
        oracle_environment_sha256,
    )
    files = _security_source_files(workspace)
    if tenant_policy_applies:
        tenant_read_scopes[""] = {"calls": (), "bindings": {}, "_policy_applies": True}
    if len(files) > MAX_SECURITY_SOURCE_FILES:
        blocked = _blocked_security_scan_report(
            workspace,
            files,
            tenant_read_calls,
            tenant_read_bindings,
            tenant_policy_applies,
        )
        if any(value is not None for value in evidence):
            blocked["runtime_oracles"] = {
                "state": "NOT_VERIFIED",
                "reason": "SOURCE_LIMIT_EXCEEDED",
                "requested": True,
                "reconciled_count": 0,
                "reconciled": [],
                "authority": "none",
                "claim_boundary": "Supplied runtime evidence was not evaluated because source coverage exceeds the scanner limit.",
            }
        return _seal_security_scan(blocked)
    database_context = {}
    bindings, findings, counts, outcomes, oracle_edges, oracle_configuration = (
        _scan_security_sources(
            workspace,
            files,
            tenant_read_calls,
            tenant_read_bindings,
            tenant_read_scopes,
            cache_enabled=cache_enabled,
            database_context=database_context,
        )
    )
    result = _security_scan_report(
        files,
        findings,
        bindings,
        counts,
        outcomes,
        tenant_read_calls,
        tenant_read_bindings,
        oracle_edges,
        oracle_configuration,
        database_context,
        tenant_policy_applies,
    )
    return (
        _reconcile_runtime_oracles(workspace, result, evidence)
        if any(value is not None for value in evidence)
        else result
    )


def security_evals() -> dict[str, Any]:
    """Evaluate security rules against fixed adversarial and safe-control fixtures."""
    fixture_path = Path(__file__).parent / "data" / "security_evals.json"
    fixtures = json.loads(fixture_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for item in fixtures:
        name, source, expected = item["name"], item["source"], set(item["expected"])
        tree = ast.parse(source, filename=f"{name}.py")
        calls = _tenant_contract_calls(tuple(item.get("tenant_read_calls", ())))
        bindings = _tenant_contract_bindings(
            tuple(item.get("tenant_read_bindings", ())), calls
        )
        findings = _security_scan_tree(
            Path("."), Path(f"{name}.py"), tree, calls, bindings
        )
        actual = {item["code"] for item in findings}
        passed = actual == expected
        rows.append(
            {
                "id": name,
                "expected": sorted(expected),
                "observed": sorted(actual),
                "passed": passed,
            }
        )
    fixture_expectations = [set(item["expected"]) for item in fixtures]
    attempted = sum(bool(expected) for expected in fixture_expectations)
    caught = sum(
        row["passed"] for row, expected in zip(rows, fixture_expectations) if expected
    )
    controls = sum(not expected for expected in fixture_expectations)
    controls_passed = sum(
        row["passed"]
        for row, expected in zip(rows, fixture_expectations)
        if not expected
    )
    state = "PASS" if all(row["passed"] for row in rows) else "BLOCKED"
    result: dict[str, Any] = {
        "schema": "factory.security-evals.v1",
        "marker": "SECURITY_EVALS_COMPLETE",
        "state": state,
        "fixtures": rows,
        "mutation_coverage": {
            "attempted": attempted,
            "caught": caught,
            "rate": round(caught / attempted, 4) if attempted else 1.0,
        },
        "safe_controls": {"attempted": controls, "passed": controls_passed},
        "authority": {
            "execution": False,
            "approval": False,
            "publication": False,
            "deployment": False,
        },
        "claim_boundary": "Fixed local AST evaluation of scanner rules only; not a penetration test, runtime exploit proof, dependency advisory, or release approval.",
    }
    result["audit_sha256"] = sha256(
        json.dumps(
            result, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    result["action_summary"] = (
        "All adversarial fixtures were caught and safe controls remained clean."
        if state == "PASS"
        else "A scanner rule failed an adversarial fixture or contaminated a safe control; block promotion and repair the evaluator."
    )
    return result
