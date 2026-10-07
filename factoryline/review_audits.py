"""Read-only Python pattern and guard-path audits; never release authority.

These are bounded syntactic analyses, not a symbolic executor or a security
certification. A declared guard must raise on denial and must not be rebound.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from hashlib import sha256
import json
import operator
from pathlib import Path, PureWindowsPath
import re
from typing import Any

SCHEMA = "factory.review-audit-policy.v1"
FINGERPRINT_SCHEMA = "factory.code-review-fingerprint.v1"
SECURITY_SCHEMA = "factory.security-audit.v1"
TENANT_CONTRACT_SCHEMA = "factory.tenant-read-contract.v1"
MAX_SECURITY_SOURCE_FILES = 460
MAX_BYTES = 1_000_000
MAX_RULES = 128
MAX_PATHS = 64
ORIGINS = {"human_confirmed", "trusted_source", "observed_production", "agent_proposed"}
NAME = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")


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
    if not isinstance(selected, (ast.FunctionDef, ast.AsyncFunctionDef)):
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


def _call_name(node: ast.Call) -> str:
    return _name(node.func)


def _security_aliases(nodes: list[ast.AST]) -> dict[str, str]:
    """Resolve common import aliases before applying security rules."""
    aliases: dict[str, str] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name == "*":
                    continue
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def _module_security_aliases(tree: ast.Module) -> dict[str, str]:
    """Resolve only imports in module scope for test-oracle attribution."""
    return _security_aliases(
        [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    )


def _scope_body(node: ast.AST) -> list[ast.stmt] | None:
    if isinstance(node, ast.Module):
        return node.body
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return node.body
    return None


def _scope_parameters(node: ast.AST) -> set[str]:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
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
    if arguments.vararg:
        names.add(arguments.vararg.arg)
    if arguments.kwarg:
        names.add(arguments.kwarg.arg)
    return names


def _binding_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return node.id
    if isinstance(node, ast.arg):
        return node.arg
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    if isinstance(node, ast.ExceptHandler):
        return node.name
    if isinstance(node, (ast.MatchAs, ast.MatchStar)):
        return node.name
    if isinstance(node, ast.MatchMapping):
        return node.rest
    return None


def _bound_names(statement: ast.AST) -> set[str]:
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
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if child is statement:
                names.add(child.name)
            continue
        if isinstance(child, ast.Lambda):
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
    nodes = [child for statement in node.body for child in _body_nodes(statement)]
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
    return _security_finding(
        "SECURITY_DYNAMIC_EXECUTION",
        relative,
        node,
        "Dynamic code execution is reachable from source.",
        "HIGH",
        call=call,
    )


def _os_command_finding(
    call: str, relative: str, node: ast.AST
) -> dict[str, Any] | None:
    if call != "os.system":
        return None
    return _security_finding(
        "SECURITY_OS_COMMAND",
        relative,
        node,
        "os.system invokes a shell and should be replaced with an argv-based process boundary.",
        "HIGH",
    )


def _shell_command_finding(
    call: str, relative: str, node: ast.Call
) -> dict[str, Any] | None:
    if call not in {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
    }:
        return None
    shell = next(
        (keyword.value for keyword in node.keywords if keyword.arg == "shell"), None
    )
    if not isinstance(shell, ast.Constant) or shell.value is not True:
        return None
    return _security_finding(
        "SECURITY_SHELL_COMMAND",
        relative,
        node,
        "subprocess shell execution is enabled; shell metacharacters can cross the command boundary.",
        "HIGH",
        call=call,
    )


def _unsafe_deserialization_finding(
    call: str, relative: str, node: ast.AST
) -> dict[str, Any] | None:
    if call not in {"pickle.load", "pickle.loads", "dill.load", "dill.loads"}:
        return None
    return _security_finding(
        "SECURITY_UNSAFE_DESERIALIZATION",
        relative,
        node,
        "Pickle-like deserialization can execute attacker-controlled code.",
        "HIGH",
        call=call,
    )


def _unsafe_yaml_finding(
    call: str, relative: str, node: ast.Call
) -> dict[str, Any] | None:
    if call not in {"yaml.load", "yaml.unsafe_load", "yaml.full_load"}:
        return None
    loader = next(
        (keyword.value for keyword in node.keywords if keyword.arg == "Loader"), None
    )
    loader_name = _name(loader) if isinstance(loader, ast.AST) else ""
    unsafe_loader = loader_name.endswith("UnsafeLoader") or loader_name.endswith(
        "FullLoader"
    )
    if call == "yaml.load" and loader is not None and not unsafe_loader:
        return None
    return _security_finding(
        "SECURITY_UNSAFE_YAML",
        relative,
        node,
        "YAML is loaded without an explicit reviewed Loader.",
        "HIGH",
        call=call,
    )


def _disabled_tls_finding(
    call: str, relative: str, node: ast.Call
) -> dict[str, Any] | None:
    if call not in {"requests.get", "requests.post", "httpx.get", "httpx.post"}:
        return None
    verify = next(
        (keyword.value for keyword in node.keywords if keyword.arg == "verify"), None
    )
    if not isinstance(verify, ast.Constant) or verify.value is not False:
        return None
    return _security_finding(
        "SECURITY_TLS_VERIFY_DISABLED",
        relative,
        node,
        "TLS certificate verification is disabled for an outbound request.",
        "HIGH",
        call=call,
    )


def _security_call_finding(
    call: str, relative: str, node: ast.Call
) -> dict[str, Any] | None:
    detectors = (
        _dynamic_execution_finding,
        _os_command_finding,
        _shell_command_finding,
        _unsafe_deserialization_finding,
        _unsafe_yaml_finding,
        _disabled_tls_finding,
    )
    for detect in detectors:
        finding = detect(call, relative, node)
        if finding is not None:
            return finding
    return None


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
        or len(value.value) < 8
        or _PLACEHOLDER_SECRET.match(value.value.strip())
    ):
        return None
    return value.value


def _literal_assignment_diagnostic(
    relative: str, node: ast.Assign | ast.AnnAssign, target: ast.expr
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
    )


def _literal_assignment_diagnostics(
    relative: str, node: ast.Assign | ast.AnnAssign
) -> list[dict[str, Any]]:
    value = _secret_literal(node)
    if value is None:
        return []
    # Evaluate the exception at the input boundary; diagnostic builders receive
    # only symbol/location metadata, never the credential literal itself.
    if relative.startswith("tests/") and re.search(
        r"(?i)(?:do[-_ ]not|fake|dummy|fixture|not[-_ ]real|test)", value
    ):
        return []
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    findings = []
    for target in targets:
        finding = _literal_assignment_diagnostic(relative, node, target)
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
    # Compare ignore markers against workspace-relative parts only.  Looking at
    # absolute ``path.parts`` made every Linux checkout rooted at ``/tmp`` look
    # like a generated temporary tree, causing the scanner to silently inspect
    # zero files and report CLEAN.  A security scan must never become weaker
    # because the workspace happens to live under an ignored-looking parent.
    files = []
    for path in root.rglob("*.py"):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(root).parts
        if ignored.intersection(relative_parts):
            continue
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


def _direct_test_vacuous_assertions(node: ast.AST) -> set[int]:
    """Track immutable direct assignments in source order, failing closed in branches."""
    body = _scope_body(node)
    if body is None:
        return set()
    known: dict[str, Any] = {}
    vacuous: set[int] = set()
    for statement in body:
        if isinstance(statement, ast.Assert):
            if _vacuous_assertion(statement.test, known):
                vacuous.add(id(statement))
            continue
        _remember_direct_constant_assignment(statement, known)
    return vacuous


def _remember_direct_constant_assignment(
    statement: ast.stmt, known: dict[str, Any]
) -> None:
    targets: list[ast.expr] = []
    value: Any = _UNKNOWN_CONSTANT
    if any(
        isinstance(item, (ast.Call, ast.Subscript)) for item in _body_nodes(statement)
    ):
        for name, prior in list(known.items()):
            if isinstance(prior, (list, dict, set, tuple)):
                known.pop(name, None)
    if isinstance(statement, ast.Assign):
        value = _constant_value(statement.value, known)
        targets = statement.targets
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        value = _constant_value(statement.value, known)
        targets = [statement.target]
    for name in _bound_names(statement):
        known.pop(name, None)
    if value is _UNKNOWN_CONSTANT:
        return
    for target in targets:
        if isinstance(target, ast.Name):
            known[target.id] = value


def _vacuous_assertion(node: ast.expr, known: dict[str, Any] | None = None) -> bool:
    if _constant_truth_value(node, known or {}) is True:
        return True
    value = _constant_value(node, known)
    if value is not _UNKNOWN_CONSTANT:
        return bool(value)
    if isinstance(node, ast.Constant):
        return bool(node.value)
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
    # Repeated calls may return different values. Never call these tautologies.
    if any(isinstance(n, (ast.Call, ast.Await)) for x in operands for n in ast.walk(x)):
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
        or (
            unittest_context
            and leaf in _UNITTEST_ASSERTIONS
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in {"self", "cls"}
        )
        or name in (helper_names or set())
    )


def _unittest_test_methods(tree: ast.Module, aliases: dict[str, str]) -> set[int]:
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    base_names: dict[str, tuple[str, ...]] = {}
    for name, node in classes.items():
        normalized = []
        for base in node.bases:
            base_name = _name(base)
            head, *tail = base_name.split(".")
            normalized.append(".".join([aliases.get(head, head), *tail]))
        base_names[name] = tuple(normalized)

    def derives_from_testcase(name: str, seen: set[str] | None = None) -> bool:
        seen = set() if seen is None else seen
        if name in seen:
            return False
        seen.add(name)
        for base in base_names.get(name, ()):
            if base in {"unittest.TestCase", "unittest.case.TestCase"}:
                return True
            if base in classes and derives_from_testcase(base, seen):
                return True
        return False

    return {
        id(method)
        for name, class_node in classes.items()
        if derives_from_testcase(name)
        for method in class_node.body
        if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _unconditionally_skipped_test(node: ast.AST) -> bool:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = _name(target)
        if name in {"skip", "pytest.mark.skip", "unittest.skip"} or name.endswith(
            ".mark.skip"
        ):
            return True
    return False


def _meaningful_local_assertion(
    node: ast.AST, aliases: dict[str, str], helper_names: set[str] | None = None
) -> bool:
    nodes = _test_oracle_body_nodes(node, aliases)
    vacuous = _direct_test_vacuous_assertions(node)
    return any(_assertion_call(child, aliases, helper_names) for child in nodes) or any(
        isinstance(child, ast.Assert)
        and id(child) not in vacuous
        and not _vacuous_assertion(child.test)
        for child in nodes
    )


def _local_assertion_helpers(tree: ast.Module, aliases: dict[str, str]) -> set[str]:
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not node.name.startswith("test_")
    }
    helpers: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, node in functions.items():
            if name not in helpers and _meaningful_local_assertion(
                node, _scope_security_aliases(aliases, node), helpers
            ):
                helpers.add(name)
                changed = True
    return helpers


def _weak_assertion_reason(
    node: ast.AST, aliases: dict[str, str] | None = None
) -> str | None:
    if isinstance(node, ast.Call):
        leaf = _normalized_call_name(node, aliases or {}).rsplit(".", 1)[-1]
        if leaf == "assertIsNotNone" or (
            leaf == "assertIs"
            and len(node.args) == 2
            and any(
                isinstance(argument, ast.Constant) and argument.value is None
                for argument in node.args
            )
        ):
            return "non-null assertion does not verify the expected behavior"
        if leaf in {"assert_called", "assert_called_once", "assert_called_once_with"}:
            return "mock invocation state does not verify its result or arguments"
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        if isinstance(node.ops[0], (ast.Eq, ast.Is)) and len(node.comparators) == 1:
            left = node.left
            right = node.comparators[0]
            if (
                any(isinstance(value, ast.Call) for value in ast.walk(left))
                and any(isinstance(value, ast.Call) for value in ast.walk(right))
                and ast.dump(left) == ast.dump(right)
            ):
                return "repeated invocation compares a result to itself instead of an independent expected value"
        if isinstance(node.ops[0], ast.IsNot) and any(
            isinstance(value, ast.Constant) and value.value is None
            for value in (node.left, *node.comparators)
        ):
            return "non-null assertion does not verify the expected behavior"
        operands = (node.left, *node.comparators)
        if any(
            isinstance(value, ast.Attribute) and value.attr in {"called", "call_count"}
            for operand in operands
            for value in ast.walk(operand)
        ):
            return "mock invocation state does not verify its result or arguments"
    if isinstance(node, ast.Attribute) and node.attr in {"called", "call_count"}:
        return "mock invocation state does not verify its result or arguments"
    return None


def _weak_test_oracle_finding(
    relative: str,
    node: ast.AST,
    aliases: dict[str, str],
    helper_names: set[str] | None = None,
    *,
    unittest_context: bool = False,
) -> dict[str, Any] | None:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    if not node.name.startswith("test_"):
        return None
    if _unconditionally_skipped_test(node):
        return None
    nodes = _test_oracle_body_nodes(node, aliases)
    vacuous = _direct_test_vacuous_assertions(node)
    weak = [
        (child, _weak_assertion_reason(child.test, aliases))
        for child in nodes
        if isinstance(child, ast.Assert)
    ]
    weak.extend(
        (child, _weak_assertion_reason(child, aliases))
        for child in nodes
        if isinstance(child, ast.Call)
        and _assertion_call(
            child, aliases, helper_names, unittest_context=unittest_context
        )
    )
    weak = [(child, reason) for child, reason in weak if reason]
    strong_assertions = [
        child
        for child in nodes
        if isinstance(child, ast.Assert)
        and id(child) not in vacuous
        and not _vacuous_assertion(child.test)
        and _weak_assertion_reason(child.test, aliases) is None
    ]
    strong_assertion_calls = [
        child
        for child in nodes
        if isinstance(child, ast.Call)
        and _assertion_call(
            child, aliases, helper_names, unittest_context=unittest_context
        )
        and _weak_assertion_reason(child, aliases) is None
    ]
    if not weak or strong_assertions or strong_assertion_calls:
        return None
    reasons = sorted({reason for _, reason in weak})
    return _security_finding(
        "QUALITY_WEAK_TEST_ORACLE",
        relative,
        weak[0][0],
        "; ".join(reasons) + ". Assert the independently expected value or state.",
        "MEDIUM",
        symbol=node.name,
        reasons=reasons,
    )


def _hollow_test_finding(
    relative: str,
    node: ast.AST,
    aliases: dict[str, str],
    helper_names: set[str] | None = None,
    *,
    unittest_context: bool = False,
) -> dict[str, Any] | None:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    if not node.name.startswith("test_"):
        return None
    if _unconditionally_skipped_test(node):
        return None
    nodes = _test_oracle_body_nodes(node, aliases)
    vacuous = _direct_test_vacuous_assertions(node)
    assertions = [n for n in nodes if isinstance(n, ast.Assert)]
    if any(
        _assertion_call(n, aliases, helper_names, unittest_context=unittest_context)
        for n in nodes
    ):
        return None
    if any(
        isinstance(child, ast.Call)
        and isinstance(child.func, ast.Name)
        and child.func.id in (helper_names or set())
        for child in nodes
    ):
        return None
    if assertions and any(
        id(assertion) not in vacuous and not _vacuous_assertion(assertion.test)
        for assertion in assertions
    ):
        return None
    return _security_finding(
        "QUALITY_HOLLOW_TEST",
        relative,
        node,
        "Test has no local non-vacuous assertion. Add an independent expected outcome and a negative control; delegated helper checks need separate evidence.",
        "MEDIUM",
        symbol=node.name,
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
        return (), (), {"path": relative, "state": "missing"}
    try:
        data, evidence = _read(workspace, relative)
        contract = json.loads(data, object_pairs_hook=_unique_fields)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReviewAuditError(f"Invalid tenant-read contract: {exc}") from exc
    if not isinstance(contract, dict) or set(contract) != {"schema", "reads"}:
        raise ReviewAuditError("Invalid tenant-read contract schema or fields.")
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
    evidence["state"] = "loaded"
    return normalized_calls, flattened, evidence


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
    if len(parts) != 3 or not parts[2].isidentifier():
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
            names.discard(child.name)
        elif isinstance(child, ast.MatchMapping) and child.rest:
            names.discard(child.rest)
        elif isinstance(child, ast.ExceptHandler) and child.name:
            names.discard(child.name)


def _tenant_discard_written_names(
    statement: ast.AST, names: set[str], comprehension_targets: set[int]
) -> None:
    for child in _body_nodes(statement):
        if (
            isinstance(child, ast.Name)
            and id(child) not in comprehension_targets
            and isinstance(child.ctx, (ast.Store, ast.Del))
        ):
            names.discard(child.id)


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
    if isinstance(value, ast.Name) and value.id in names:
        names.add(target.id)
    else:
        names.discard(target.id)
        if value is not None:
            _tenant_discard_written_names(value, names, comprehension_targets)
    return True


def _tenant_bound_names(function: ast.AST, parameter: str, use: ast.Call) -> set[str]:
    """Track simple, unconditional tenant aliases and invalidate later writes."""
    names = {parameter}
    comprehension_targets = _tenant_comprehension_targets(function)
    for statement in function.body:
        if (statement.lineno, statement.col_offset) >= (use.lineno, use.col_offset):
            break
        _tenant_discard_captures(statement, names)
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
            isinstance(value, ast.Name)
            and value.id in _tenant_bound_names(function, parameter, node)
            and parameter in parameters
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
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        for finding in _tenant_function_findings(
            relative, function, calls, aliases, bindings
        )
    ]


def _undeclared_tenant_read_findings(
    relative: str,
    nodes: list[ast.AST],
    aliases: dict[str, str],
    declared_reads: set[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for call_name, call in _orm_read_candidates(nodes, aliases):
        if call_name not in declared_reads:
            findings.append(
                _security_finding(
                    "SECURITY_TENANT_READ_UNDECLARED",
                    relative,
                    call,
                    (
                        f"Potential ORM read {call_name} is outside the declared tenant-read contract. "
                        "Add the read to --tenant-read-call and bind its tenant scope, or document why tenant isolation does not apply."
                    ),
                    "HIGH",
                    call=call_name,
                )
            )
    return findings


def _test_oracle_findings(
    relative: str,
    nodes: list[ast.AST],
    aliases: dict[str, str],
    helper_names: set[str],
    unittest_methods: set[int],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for node in nodes:
        is_unittest_method = id(node) in unittest_methods
        scoped_aliases = (
            _scope_security_aliases(aliases, node)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
            else aliases
        )
        hollow = _hollow_test_finding(
            relative,
            node,
            scoped_aliases,
            helper_names,
            unittest_context=is_unittest_method,
        )
        if hollow is not None:
            findings.append(hollow)
        weak = _weak_test_oracle_finding(
            relative,
            node,
            scoped_aliases,
            helper_names,
            unittest_context=is_unittest_method,
        )
        if weak is not None:
            findings.append(weak)
    return findings


def _security_node_findings(
    relative: str, node: ast.AST, aliases: dict[str, str]
) -> list[dict[str, Any]]:
    if isinstance(node, ast.Call):
        call = _normalized_call_name(node, aliases)
        finding = _security_call_finding(call, relative, node)
        return [finding] if finding is not None else []
    if isinstance(node, ast.ExceptHandler):
        finding = _bare_except_finding(relative, node)
        return [finding] if finding is not None else []
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        return _literal_assignment_diagnostics(relative, node)
    return []


def _security_scan_tree(
    root: Path,
    path: Path,
    tree: ast.AST,
    tenant_read_calls: tuple[str, ...] = (),
    tenant_read_bindings: dict[str, tuple[str, ...]] | None = None,
) -> list[dict[str, Any]]:
    relative = path.relative_to(root).as_posix()
    nodes = list(ast.walk(tree))
    aliases = _security_aliases(nodes)
    oracle_aliases = _scope_security_aliases(_module_security_aliases(tree), tree)
    helper_names = _local_assertion_helpers(tree, oracle_aliases)
    unittest_methods = _unittest_test_methods(tree, oracle_aliases)
    findings = _tenant_read_findings(
        relative, nodes, tenant_read_calls, aliases, tenant_read_bindings or {}
    )
    findings.extend(
        _undeclared_tenant_read_findings(
            relative, nodes, aliases, set(tenant_read_calls)
        )
    )
    findings.extend(
        _test_oracle_findings(
            relative, nodes, oracle_aliases, helper_names, unittest_methods
        )
    )
    for node in nodes:
        findings.extend(_security_node_findings(relative, node, aliases))
    return findings


def _security_scan_file(
    workspace: Path,
    path: Path,
    tenant_read_calls: tuple[str, ...] = (),
    tenant_read_bindings: dict[str, tuple[str, ...]] | None = None,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], str]:
    """Scan one bounded Python source and return its byte binding and findings."""
    relative = path.relative_to(workspace).as_posix()
    binding: dict[str, Any] | None = None
    try:
        initial_size = path.stat().st_size
        if initial_size > MAX_BYTES:
            return (
                None,
                [
                    _security_finding(
                        "SECURITY_SOURCE_TOO_LARGE",
                        relative,
                        ast.Module(body=[], type_ignores=[]),
                        f"Source exceeds the {MAX_BYTES}-byte scan limit.",
                        "HIGH",
                        bytes=initial_size,
                    )
                ],
                "too_large",
            )
        with path.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        final_size = path.stat().st_size
        if len(data) > MAX_BYTES or final_size > MAX_BYTES:
            return (
                None,
                [
                    _security_finding(
                        "SECURITY_SOURCE_TOO_LARGE",
                        relative,
                        ast.Module(body=[], type_ignores=[]),
                        f"Source exceeds the {MAX_BYTES}-byte scan limit.",
                        "HIGH",
                        bytes=max(len(data), final_size),
                    )
                ],
                "too_large",
            )
        binding = {
            "path": relative,
            "sha256": sha256(data).hexdigest(),
            "bytes": len(data),
        }
        tree = ast.parse(data, filename=str(path))
    except SyntaxError as exc:
        return (
            binding,
            [
                _security_finding(
                    "QUALITY_SYNTAX_ERROR",
                    relative,
                    exc,
                    "Python source cannot be parsed deterministically.",
                    "HIGH",
                    detail=str(exc),
                )
            ],
            "syntax_error",
        )
    except (OSError, UnicodeError) as exc:
        return (
            binding,
            [
                _security_finding(
                    "SECURITY_SOURCE_UNREADABLE",
                    relative,
                    ast.Module(body=[], type_ignores=[]),
                    "Source could not be read for security analysis.",
                    "HIGH",
                    detail=type(exc).__name__,
                )
            ],
            "unreadable",
        )
    return (
        binding,
        _security_scan_tree(
            workspace, path, tree, tenant_read_calls, tenant_read_bindings
        ),
        "audited",
    )


def _verify_security_bindings(workspace: Path, bindings: list[dict[str, Any]]) -> None:
    """Reject a source that changes after its scan but before receipt creation."""
    for binding in bindings:
        current = workspace / binding["path"]
        try:
            if current.stat().st_size > MAX_BYTES:
                raise ReviewAuditError(
                    f"Evidence changed during security scan: {binding['path']}"
                )
            with current.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES or current.stat().st_size > MAX_BYTES:
                raise ReviewAuditError(
                    f"Evidence changed during security scan: {binding['path']}"
                )
        except (OSError, UnicodeError) as exc:
            raise ReviewAuditError(
                f"Evidence changed during security scan: {binding['path']}"
            ) from exc
        if (
            len(data) != binding["bytes"]
            or sha256(data).hexdigest() != binding["sha256"]
        ):
            raise ReviewAuditError(
                f"Evidence changed during security scan: {binding['path']}"
            )


def _blocked_security_scan_report(
    workspace: Path,
    files: list[Path],
    tenant_read_calls: tuple[str, ...],
    tenant_read_bindings: dict[str, tuple[str, ...]],
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
            tenant_read_calls, tenant_read_bindings
        ),
        "sources": [],
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
) -> dict[str, Any]:
    return {
        "calls": list(tenant_read_calls),
        "keyword": "tenant_id",
        "legacy_binding": "keyword:tenant_id:tenant_id",
        "argument_bindings": {
            call: list(bindings) for call, bindings in tenant_read_bindings.items()
        },
        "identity_authentication_proven": False,
    }


def _scan_security_sources(
    workspace: Path,
    files: list[Path],
    tenant_read_calls: tuple[str, ...],
    tenant_read_bindings: dict[str, tuple[str, ...]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int], dict[str, int]]:
    findings: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    outcomes = {"syntax_error": 0, "unreadable": 0, "too_large": 0, "audited": 0}
    for path in files:
        binding, file_findings, outcome = _security_scan_file(
            workspace, path, tenant_read_calls, tenant_read_bindings
        )
        if binding is not None:
            bindings.append(binding)
        findings.extend(file_findings)
        if outcome in outcomes:
            outcomes[outcome] += 1
    _verify_security_bindings(workspace, bindings)
    findings.sort(
        key=lambda item: (item["path"], item["line"], item["code"], item["column"])
    )
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["code"]] = counts.get(finding["code"], 0) + 1
    return bindings, findings, counts, outcomes


def _security_scan_state(files: list[Path], findings: list[dict[str, Any]]) -> str:
    if not files:
        return "NO_SOURCES"
    if any(item["severity"] in {"CRITICAL", "HIGH"} for item in findings):
        return "BLOCKED"
    return "FINDINGS" if findings else "CLEAN"


def _security_scan_coverage(
    files: list[Path], outcomes: dict[str, int]
) -> dict[str, Any]:
    audited = outcomes["audited"]
    attempted = len(files)
    complete = bool(files) and attempted == audited
    if not files:
        measurement_state = "no_eligible_sources"
    elif complete:
        measurement_state = "complete"
    else:
        measurement_state = "incomplete"
    return {
        "language": "Python",
        "files_discovered": len(files),
        "files_attempted": attempted,
        "files_audited": audited,
        "audit_rate": round(audited / len(files), 4) if files else None,
        "rate_defined": bool(files),
        "inventory_complete": True,
        "measurement_state": measurement_state,
        "complete": complete,
        "limit": MAX_SECURITY_SOURCE_FILES,
    }


def _seal_security_scan(core: dict[str, Any]) -> dict[str, Any]:
    core["audit_sha256"] = sha256(
        json.dumps(
            core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    return core


def _security_scan_action_summary(state: str) -> str:
    if state == "NO_SOURCES":
        return (
            "No eligible Python sources were found; no security conclusions were drawn."
        )
    if state == "CLEAN":
        return "No high-risk static security or quality patterns found."
    return "Resolve each listed finding and rerun this deterministic scan before release review."


def _security_scan_report(
    files: list[Path],
    findings: list[dict[str, Any]],
    bindings: list[dict[str, Any]],
    counts: dict[str, int],
    outcomes: dict[str, int],
    tenant_read_calls: tuple[str, ...],
    tenant_read_bindings: dict[str, tuple[str, ...]],
) -> dict[str, Any]:
    state = _security_scan_state(files, findings)
    core: dict[str, Any] = {
        "schema": SECURITY_SCHEMA,
        "marker": "SECURITY_AUDIT_COMPLETE",
        "state": state,
        "files_scanned": len(bindings),
        "parse_errors": outcomes["syntax_error"],
        "unreadable_sources": outcomes["unreadable"],
        "oversized_sources": outcomes["too_large"],
        "audit_coverage": _security_scan_coverage(files, outcomes),
        "tenant_read_contract": _tenant_read_contract(
            tenant_read_calls, tenant_read_bindings
        ),
        "sources": bindings,
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
    core["action_summary"] = _security_scan_action_summary(state)
    return _seal_security_scan(core)


def security_scan(
    root: Path,
    *,
    tenant_read_calls: tuple[str, ...] = (),
    tenant_read_bindings: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Run a bounded AST security and code-quality scan without importing or executing source."""
    workspace = Path(root).resolve()
    tenant_read_calls = _tenant_contract_calls(tenant_read_calls)
    tenant_read_bindings = _tenant_contract_bindings(
        tenant_read_bindings, tenant_read_calls
    )
    files = _security_source_files(workspace)
    if len(files) > MAX_SECURITY_SOURCE_FILES:
        return _blocked_security_scan_report(
            workspace, files, tenant_read_calls, tenant_read_bindings
        )
    bindings, findings, counts, outcomes = _scan_security_sources(
        workspace, files, tenant_read_calls, tenant_read_bindings
    )
    return _security_scan_report(
        files,
        findings,
        bindings,
        counts,
        outcomes,
        tenant_read_calls,
        tenant_read_bindings,
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
