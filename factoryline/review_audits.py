"""Read-only Python pattern and guard-path audits; never release authority.

These are bounded syntactic analyses, not a symbolic executor or a security
certification. A declared guard must raise on denial and must not be rebound.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path, PureWindowsPath
import re
from typing import Any

SCHEMA = "factory.review-audit-policy.v1"
FINGERPRINT_SCHEMA = "factory.code-review-fingerprint.v1"
SECURITY_SCHEMA = "factory.security-audit.v1"
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


def _read(root: Path, path: str) -> tuple[bytes, dict]:
    if not isinstance(path, str) or not path or "\\" in path:
        raise ReviewAuditError("Use a nonempty workspace-relative POSIX path.")
    relative = Path(path)
    if relative.is_absolute() or PureWindowsPath(path).drive or ".." in relative.parts:
        raise ReviewAuditError(f"Path escapes workspace: {path}")
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


def _prepare(root: Path, policy: dict, cache: dict) -> tuple[list, list]:
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
    seen: set[str] = set()
    patterns, guards = [], []
    for value in groups:
        rule = _rule(value, seen, {"members", "required_calls"})
        calls = _call_names(rule["required_calls"])
        if not isinstance(rule["members"], list) or not 2 <= len(rule["members"]) <= 32:
            raise ReviewAuditError("Pattern groups require 2..32 peers.")
        members = [_target(root, item, cache) for item in rule["members"]]
        if len({(t["path"], t["symbol"]) for t, _ in members}) != len(members):
            raise ReviewAuditError("Duplicate peer target.")
        patterns.append((rule, members, calls))
    for value in effects:
        rule = _rule(value, seen, {"target", "guard_call", "effect_call"})
        _call_names([rule["guard_call"], rule["effect_call"]])
        target, node = _target(root, rule["target"], cache)
        guards.append((rule, target, node))
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


def _security_aliases(tree: ast.AST) -> dict[str, str]:
    """Resolve common import aliases before applying security rules."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name == "*":
                    continue
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def _normalized_call_name(node: ast.Call, aliases: dict[str, str]) -> str:
    name = _call_name(node)
    if not name:
        return name
    head, *tail = name.split(".")
    return ".".join([aliases.get(head, head), *tail])


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
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())[:512]


def _security_scan_tree(root: Path, path: Path, tree: ast.AST) -> list[dict[str, Any]]:
    relative = path.relative_to(root).as_posix()
    findings: list[dict[str, Any]] = []
    aliases = _security_aliases(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call = _normalized_call_name(node, aliases)
            if call in {"eval", "exec", "builtins.eval", "builtins.exec"}:
                findings.append(
                    _security_finding(
                        "SECURITY_DYNAMIC_EXECUTION",
                        relative,
                        node,
                        "Dynamic code execution is reachable from source.",
                        "HIGH",
                        call=call,
                    )
                )
            elif call == "os.system":
                findings.append(
                    _security_finding(
                        "SECURITY_OS_COMMAND",
                        relative,
                        node,
                        "os.system invokes a shell and should be replaced with an argv-based process boundary.",
                        "HIGH",
                    )
                )
            elif call in {
                "subprocess.run",
                "subprocess.Popen",
                "subprocess.call",
                "subprocess.check_call",
                "subprocess.check_output",
            }:
                shell = next(
                    (
                        keyword.value
                        for keyword in node.keywords
                        if keyword.arg == "shell"
                    ),
                    None,
                )
                if isinstance(shell, ast.Constant) and shell.value is True:
                    findings.append(
                        _security_finding(
                            "SECURITY_SHELL_COMMAND",
                            relative,
                            node,
                            "subprocess shell execution is enabled; shell metacharacters can cross the command boundary.",
                            "HIGH",
                            call=call,
                        )
                    )
            elif call in {"pickle.load", "pickle.loads", "dill.load", "dill.loads"}:
                findings.append(
                    _security_finding(
                        "SECURITY_UNSAFE_DESERIALIZATION",
                        relative,
                        node,
                        "Pickle-like deserialization can execute attacker-controlled code.",
                        "HIGH",
                        call=call,
                    )
                )
            elif call in {"yaml.load", "yaml.unsafe_load", "yaml.full_load"}:
                loader = next(
                    (
                        keyword.value
                        for keyword in node.keywords
                        if keyword.arg == "Loader"
                    ),
                    None,
                )
                loader_name = _name(loader) if isinstance(loader, ast.AST) else ""
                unsafe_loader = loader_name.endswith(
                    "UnsafeLoader"
                ) or loader_name.endswith("FullLoader")
                if call != "yaml.load" or loader is None or unsafe_loader:
                    findings.append(
                        _security_finding(
                            "SECURITY_UNSAFE_YAML",
                            relative,
                            node,
                            "YAML is loaded without an explicit reviewed Loader.",
                            "HIGH",
                            call=call,
                        )
                    )
            elif call in {"requests.get", "requests.post", "httpx.get", "httpx.post"}:
                verify = next(
                    (
                        keyword.value
                        for keyword in node.keywords
                        if keyword.arg == "verify"
                    ),
                    None,
                )
                if isinstance(verify, ast.Constant) and verify.value is False:
                    findings.append(
                        _security_finding(
                            "SECURITY_TLS_VERIFY_DISABLED",
                            relative,
                            node,
                            "TLS certificate verification is disabled for an outbound request.",
                            "HIGH",
                            call=call,
                        )
                    )
        elif isinstance(node, ast.ExceptHandler) and node.type is None:
            findings.append(
                _security_finding(
                    "QUALITY_BARE_EXCEPT",
                    relative,
                    node,
                    "Bare except hides every failure type and weakens deterministic recovery.",
                    "MEDIUM",
                )
            )
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if (
                isinstance(value, ast.Constant)
                and isinstance(value.value, str)
                and len(value.value) >= 8
                and not _PLACEHOLDER_SECRET.match(value.value.strip())
            ):
                for target in targets:
                    if isinstance(target, ast.Name) and _SECRET_ASSIGNMENT.search(
                        target.id
                    ):
                        # Test fixtures may intentionally carry a non-secret sentinel to prove
                        # redaction. They are reported only when the literal is not recognizable
                        # as a fixture value, keeping the production gate strict without noise.
                        if not (
                            relative.startswith("tests/")
                            and re.search(
                                r"(?i)(?:do[-_ ]not|fake|dummy|fixture|not[-_ ]real|test)",
                                value.value,
                            )
                        ):
                            findings.append(
                                _security_finding(
                                    "SECURITY_HARDCODED_SECRET",
                                    relative,
                                    node,
                                    "Credential-like material is assigned as a source literal.",
                                    "CRITICAL",
                                    name=target.id,
                                )
                            )
    return findings


def _security_scan_file(
    workspace: Path, path: Path
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], bool]:
    """Scan one bounded Python source and return its byte binding and findings."""
    relative = path.relative_to(workspace).as_posix()
    binding: dict[str, Any] | None = None
    try:
        data = path.read_bytes()
        if len(data) > MAX_BYTES:
            return (
                None,
                [
                    _security_finding(
                        "SECURITY_SOURCE_TOO_LARGE",
                        relative,
                        ast.Module(body=[], type_ignores=[]),
                        f"Source exceeds the {MAX_BYTES}-byte scan limit.",
                        "HIGH",
                        bytes=len(data),
                    )
                ],
                False,
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
            True,
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
            True,
        )
    return binding, _security_scan_tree(workspace, path, tree), False


def _verify_security_bindings(workspace: Path, bindings: list[dict[str, Any]]) -> None:
    """Reject a source that changes after its scan but before receipt creation."""
    for binding in bindings:
        current = workspace / binding["path"]
        try:
            data = current.read_bytes()
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


def security_scan(root: Path) -> dict[str, Any]:
    """Run a bounded AST security and code-quality scan without importing or executing source."""
    workspace = Path(root).resolve()
    files = _security_source_files(workspace)
    findings: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    parse_errors = 0
    for path in files:
        binding, file_findings, parse_error = _security_scan_file(workspace, path)
        if binding is not None:
            bindings.append(binding)
        findings.extend(file_findings)
        parse_errors += int(parse_error)
    _verify_security_bindings(workspace, bindings)
    findings.sort(
        key=lambda item: (item["path"], item["line"], item["code"], item["column"])
    )
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["code"]] = counts.get(finding["code"], 0) + 1
    state = (
        "BLOCKED"
        if any(item["severity"] in {"CRITICAL", "HIGH"} for item in findings)
        else "FINDINGS"
        if findings
        else "CLEAN"
    )
    core: dict[str, Any] = {
        "schema": SECURITY_SCHEMA,
        "marker": "SECURITY_AUDIT_COMPLETE",
        "state": state,
        "files_scanned": len(bindings),
        "parse_errors": parse_errors,
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
        "claim_boundary": "Bounded Python AST pattern scan only; not a penetration test, runtime exploit proof, dependency advisory, or release approval.",
    }
    core["audit_sha256"] = sha256(
        json.dumps(
            core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    core["action_summary"] = (
        "No high-risk static security or quality patterns found."
        if state == "CLEAN"
        else "Resolve each listed finding and rerun this deterministic scan before release review."
    )
    return core


def security_evals() -> dict[str, Any]:
    """Evaluate security rules against fixed adversarial and safe-control fixtures."""
    fixtures = (
        ("dynamic-execution", "eval(value)", {"SECURITY_DYNAMIC_EXECUTION"}),
        (
            "shell-command",
            "import subprocess\nsubprocess.run(value, shell=True)",
            {"SECURITY_SHELL_COMMAND"},
        ),
        ("os-command", "import os\nos.system(value)", {"SECURITY_OS_COMMAND"}),
        (
            "unsafe-deserialization",
            "import pickle\npickle.loads(value)",
            {"SECURITY_UNSAFE_DESERIALIZATION"},
        ),
        ("unsafe-yaml", "import yaml\nyaml.load(value)", {"SECURITY_UNSAFE_YAML"}),
        (
            "tls-disabled",
            "import requests\nrequests.get(url, verify=False)",
            {"SECURITY_TLS_VERIFY_DISABLED"},
        ),
        (
            "literal-secret",
            "api_key = 'live-secret-material'",
            {"SECURITY_HARDCODED_SECRET"},
        ),
        ("bare-except", "try:\n    work()\nexcept:\n    pass", {"QUALITY_BARE_EXCEPT"}),
        (
            "safe-controls",
            "import subprocess\nimport yaml\nyaml.load(value, Loader=yaml.SafeLoader)\nsubprocess.run(['tool', value], shell=False, check=True)",
            set(),
        ),
    )
    rows: list[dict[str, Any]] = []
    for name, source, expected in fixtures:
        tree = ast.parse(source, filename=f"{name}.py")
        findings = _security_scan_tree(Path("."), Path(f"{name}.py"), tree)
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
    attempted = sum(bool(expected) for _, _, expected in fixtures)
    caught = sum(
        row["passed"] for row, (_, _, expected) in zip(rows, fixtures) if expected
    )
    controls = sum(not expected for _, _, expected in fixtures)
    controls_passed = sum(
        row["passed"] for row, (_, _, expected) in zip(rows, fixtures) if not expected
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
