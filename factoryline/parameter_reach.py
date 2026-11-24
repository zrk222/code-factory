"""Cross-function reach for parameter-sourced pattern findings (Python).

The ``*.parameter-*`` pattern rules see one function: a parameter that reaches a
shell, SQL or file sink. This pass follows that parameter to its callers and
iterates to a fixpoint, so each finding gets one of four reach states:

``entry_reached``
    An untrusted input (request data, ``sys.argv``, ``input()``, parsed CLI
    arguments, or a parameter of a route, MCP tool or CLI command handler)
    reaches the parameter through resolved calls. The chain is recorded.
``callers_constant_only``
    The function is private and every resolved call site passes a literal,
    an upper-case constant or a sanitized value.
``public_api``
    No resolved untrusted caller, and the function is public: library users
    can still call it with untrusted data.
``unresolved``
    Anything else, including calls through ``*args``/``**kwargs``.

Only ``entry_reached`` raises confidence and only ``callers_constant_only``
lowers it; the pass never removes a finding. Resolution is static and
conservative: direct names, imported names, module aliases, ``self``/``cls``
methods, and attribute calls whose method name is unique in the repository.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REACH_SCHEMA = "factory.parameter-reach.v1"
MAX_ITERATIONS = 12
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "site-packages", "__pycache__"}
_ENTRY_DECORATOR = re.compile(
    r"(?:^|\.)(route|get|post|put|patch|delete|api_view|websocket|tool|command|"
    r"group|callback|action|endpoint|resource|prompt)$"
)
_REQUEST_ATTRS = {
    "args",
    "form",
    "values",
    "json",
    "data",
    "files",
    "GET",
    "POST",
    "FILES",
    "query_params",
    "body",
    "headers",
    "cookies",
    "COOKIES",
    "META",
    "path_params",
}
_MCP_CLASS = re.compile(r"(?i)(tool|mcp|server|handler)")
_MCP_ARGUMENTS = {"arguments", "args", "params", "tool_input", "input_data", "kwargs"}
_SANITIZERS = re.compile(
    r"(?:^|\.)(quote|escape|int|float|bool|basename|secure_filename|abs|len|"
    r"Identifier|Literal|validate\w*|sanitize\w*|safe\w*)$"
)


@dataclass
class Function:
    key: str
    module: str
    path: str
    node: ast.AST
    params: list[str]
    class_name: str | None
    is_entry: bool
    public: bool


@dataclass
class Reach:
    state: str
    chain: list[str] = field(default_factory=list)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _module_name(relative: str) -> str:
    parts = relative.removesuffix(".py").split("/")
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _params(node: ast.AST, method: bool) -> list[str]:
    args = node.args
    names = [a.arg for a in [*args.posonlyargs, *args.args]]
    if method and names and names[0] in {"self", "cls"}:
        names = names[1:]
    return names + [a.arg for a in args.kwonlyargs]


def _is_entry(node: ast.AST) -> bool:
    return any(_ENTRY_DECORATOR.search(_dotted(d)) for d in node.decorator_list)


def _relative_import_prefix(module: str, is_package: bool, node: ast.ImportFrom) -> str:
    package = module if is_package else module.rpartition(".")[0]
    parts = package.split(".") if package else []
    if node.level > 1:
        parts = parts[: len(parts) - (node.level - 1)]
    return ".".join(p for p in (".".join(parts), node.module or "") if p)


def _module_imports(module: str, is_package: bool, tree: ast.Module) -> dict[str, str]:
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                prefix = _relative_import_prefix(module, is_package, node)
            else:
                prefix = node.module or ""
            for alias in node.names:
                imports[alias.asname or alias.name] = f"{prefix}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                imports[alias.asname or top] = alias.name if alias.asname else top
    return imports


class Index:
    """Functions, imports and call sites of one Python source tree."""

    def __init__(self, sources: dict[str, str]):
        self.functions: dict[str, Function] = {}
        self.by_path_line: list[tuple[str, int, int, str]] = []
        self.imports: dict[str, dict[str, str]] = {}
        self.calls: list[tuple[str, ast.Call, str]] = []  # caller key, call, module
        self.method_names: dict[str, list[str]] = {}
        self.cli_args: dict[str, set[str]] = {}
        self.trees: dict[str, ast.Module] = {}
        for relative in sorted(sources):
            if not relative.endswith(".py") or _SKIP_DIRS.intersection(
                relative.split("/")
            ):
                continue
            try:
                tree = ast.parse(sources[relative])
            except (SyntaxError, ValueError, RecursionError):
                continue
            self.trees[relative] = tree
            self._index_module(relative, tree)

    @classmethod
    def from_root(cls, root: Path) -> Index:
        sources = {}
        for path in sorted(root.rglob("*.py")):
            relative = path.relative_to(root).as_posix()
            if path.is_file() and not _SKIP_DIRS.intersection(relative.split("/")):
                try:
                    sources[relative] = path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    continue
        return cls(sources)

    def _index_module(self, relative: str, tree: ast.Module) -> None:
        module = _module_name(relative)
        is_package = relative.rsplit("/", 1)[-1] == "__init__.py"
        self.imports[module] = _module_imports(module, is_package, tree)
        private = any(
            part.startswith("_") and part != "__init__" for part in module.split(".")
        )
        self._visit(tree.body, None, "", (module, relative, private))

    def _visit(self, body, class_name: str | None, scope: str, context) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                self._visit(node.body, node.name, f"{scope}{node.name}.", context)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._add_function(node, class_name, scope, context)
                inner = f"{scope}{node.name}.<locals>."
                self._visit(node.body, class_name, inner, context)

    def _add_function(self, node, class_name, scope, context) -> None:
        module, relative, private = context
        key = f"{module}:{scope}{node.name}"
        public = not (
            node.name.startswith("_") or private or (class_name or "").startswith("_")
        )
        entry = _is_entry(node) or _is_mcp_handler(relative, node, class_name)
        params = _params(node, class_name is not None)
        self.functions[key] = Function(
            key, module, relative, node, params, class_name, entry, public
        )
        end = getattr(node, "end_lineno", node.lineno)
        self.by_path_line.append((relative, node.lineno, end, key))
        if class_name is not None:
            self.method_names.setdefault(node.name, []).append(key)
        self.cli_args[key] = _parsed_cli_names(node)
        self.calls.extend(
            (key, child, module)
            for child in ast.walk(node)
            if isinstance(child, ast.Call)
        )

    def enclosing(self, relative: str, line: int) -> Function | None:
        best = None
        for path, start, end, key in self.by_path_line:
            if path == relative and start <= line <= end:
                if best is None or start >= self.functions[best].node.lineno:
                    best = key
        return self.functions.get(best) if best else None

    def resolve(self, call: ast.Call, module: str, caller: Function) -> Function | None:
        func = call.func
        imports = self.imports.get(module, {})
        if isinstance(func, ast.Name):
            local = self.functions.get(f"{module}:{func.id}")
            if local:
                return local
            target = imports.get(func.id)
            if target and "." in target:
                mod, name = target.rsplit(".", 1)
                return self.functions.get(f"{mod}:{name}")
            return None
        if isinstance(func, ast.Attribute):
            base = func.value
            if (
                isinstance(base, ast.Name)
                and base.id in {"self", "cls"}
                and caller.class_name
            ):
                prefix = caller.key.split(":", 1)[1].split(".")[0]
                return self.functions.get(f"{module}:{prefix}.{func.attr}")
            if isinstance(base, ast.Name) and base.id in imports:
                return self.functions.get(f"{imports[base.id]}:{func.attr}")
            candidates = self.method_names.get(func.attr, [])
            if len(candidates) == 1:
                return self.functions[candidates[0]]
        return None


def _in_mcp_module(relative: str) -> bool:
    return any("mcp" in part.lower() for part in relative.split("/"))


def _is_mcp_handler(relative: str, node: ast.AST, class_name: str | None) -> bool:
    """Public methods of tool/server classes in an MCP module receive tool arguments."""
    if not _in_mcp_module(relative) or node.name.startswith("_"):
        return False
    return class_name is not None and bool(_MCP_CLASS.search(class_name))


def _parsed_cli_names(node: ast.AST) -> set[str]:
    """Names bound to ``parser.parse_args()`` results inside a function."""
    names = set()
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Assign)
            and isinstance(child.value, ast.Call)
            and _dotted(child.value.func).endswith(("parse_args", "parse_known_args"))
        ):
            names.update(t.id for t in child.targets if isinstance(t, ast.Name))
    return names


def _untrusted(expr: ast.AST, caller: Function, cli_names: set[str]) -> str | None:
    for node in ast.walk(expr):
        dotted = _dotted(node) if isinstance(node, (ast.Attribute, ast.Call)) else ""
        if isinstance(node, ast.Attribute) and node.attr in _REQUEST_ATTRS:
            if _dotted(node.value).split(".")[-1] in {"request", "req"}:
                return f"request.{node.attr}"
        if dotted in {"sys.argv", "input"} or (
            isinstance(node, ast.Subscript) and _dotted(node.value) == "sys.argv"
        ):
            return dotted or "sys.argv"
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in cli_names
        ):
            return f"cli argument {node.value.id}.{node.attr}"
        if _in_mcp_module(caller.path):
            target = None
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
            ):
                target = node.func.value
            elif isinstance(node, ast.Subscript):
                target = node.value
            if isinstance(target, ast.Name) and target.id in _MCP_ARGUMENTS:
                return f"MCP tool {target.id}"
    return None


def _classify(expr: ast.AST, caller: Function, cli_names: set[str]) -> tuple[str, str]:
    if (
        isinstance(expr, ast.Constant)
        or (isinstance(expr, ast.Name) and expr.id.isupper())
        or (
            isinstance(expr, ast.JoinedStr)
            and not any(isinstance(v, ast.FormattedValue) for v in expr.values)
        )
    ):
        return "constant", ""
    if isinstance(expr, ast.Call) and _SANITIZERS.search(_dotted(expr.func)):
        return "sanitized", _dotted(expr.func)
    source = _untrusted(expr, caller, cli_names)
    if source:
        return "untrusted", source
    names = {
        n.id
        for n in ast.walk(expr)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
    }
    params = [p for p in caller.params if p in names]
    if params:
        return "param", params[0]
    return "other", ""


def _argument(call: ast.Call, target: Function, param: str) -> ast.AST | None | str:
    """The expression bound to ``param`` at this call, ``None`` when absent, ``"*"`` when unknown."""
    if param in target.params:
        index = target.params.index(param)
        positional = [a for a in call.args]
        if any(isinstance(a, ast.Starred) for a in positional[: index + 1]):
            return "*"
        if index < len(positional):
            return positional[index]
    for keyword in call.keywords:
        if keyword.arg == param:
            return keyword.value
        if keyword.arg is None:
            return "*"
    return None


def _call_graph(index: Index) -> dict[str, list[tuple[Function, ast.Call]]]:
    callers: dict[str, list[tuple[Function, ast.Call]]] = {}
    for caller_key, call, module in index.calls:
        caller = index.functions[caller_key]
        target = index.resolve(call, module, caller)
        if target is not None and target.key != caller_key:
            callers.setdefault(target.key, []).append((caller, call))
    return callers


def _seed(index: Index, findings: list[dict], summary: dict) -> list:
    seeds = []
    for finding in findings:
        func = index.enclosing(finding["path"], finding["line"])
        if func is None or finding.get("source") not in func.params:
            seeds.append(None)
            continue
        where = f"{finding['rule']} at {finding['path']}:{finding['line']}"
        chain = [f"{func.key}({finding['source']}) -> {where}"]
        summary.setdefault(func.key, {}).setdefault(finding["source"], chain)
        seeds.append((func, finding["source"]))
    return seeds


def _call_kind(index: Index, caller: Function, call: ast.Call, func: Function, param):
    argument = _argument(call, func, param)
    if argument is None:
        return "constant", "default"
    if argument == "*":
        return "other", "starred"
    return _classify(argument, caller, index.cli_args.get(caller.key, set()))


class _Propagation:
    """Worklist fixpoint from sink parameters to untrusted callers."""

    def __init__(self, index: Index, callers, summary):
        self.index, self.callers, self.summary = index, callers, summary
        self.confirmed: dict[tuple[str, str], list[str]] = {}
        self.observed: dict[tuple[str, str], set[str]] = {}

    def run(self) -> None:
        work = [
            (key, param) for key, params in self.summary.items() for param in params
        ]
        budget = MAX_ITERATIONS * max(1, len(self.index.functions))
        while work and budget:
            budget -= 1
            key, param = work.pop()
            work.extend(self._step(key, param))
        while self._settle():
            pass

    def _step(self, key: str, param: str) -> list[tuple[str, str]]:
        func, chain = self.index.functions[key], self.summary[key][param]
        if func.is_entry:
            entry = f"entry {func.key} parameter {param}"
            self.confirmed.setdefault((key, param), [entry, *chain])
        new = []
        for caller, call in self.callers.get(key, []):
            kind, detail = _call_kind(self.index, caller, call, func, param)
            self.observed.setdefault((key, param), set()).add(kind)
            step = f"{caller.key} calls {func.key} at {caller.path}:{call.lineno}"
            if kind == "untrusted":
                origin = f"{detail} in {caller.key}"
                self.confirmed.setdefault((key, param), [origin, step, *chain])
            elif kind == "param" and detail not in self.summary.setdefault(
                caller.key, {}
            ):
                self.summary[caller.key][detail] = [step, *chain]
                new.append((caller.key, detail))
        return new

    def _settle(self) -> bool:
        """Copy a caller's confirmation down to callees processed before it."""
        changed = False
        for key, params in self.summary.items():
            for param in params:
                if (key, param) not in self.confirmed:
                    changed |= self._settle_one(key, param)
        return changed

    def _settle_one(self, key: str, param: str) -> bool:
        func = self.index.functions[key]
        for caller, call in self.callers.get(key, []):
            kind, detail = _call_kind(self.index, caller, call, func, param)
            if kind == "param" and (caller.key, detail) in self.confirmed:
                self.confirmed[(key, param)] = self.confirmed[(caller.key, detail)]
                return True
        return False

    def state(self, seed) -> Reach:
        if seed is None:
            return Reach("unresolved")
        func, param = seed
        if (func.key, param) in self.confirmed:
            return Reach("entry_reached", self.confirmed[(func.key, param)])
        kinds = self.observed.get((func.key, param), set())
        if not func.public and kinds and kinds <= {"constant", "sanitized"}:
            return Reach("callers_constant_only")
        return Reach("public_api" if func.public else "unresolved")


def reach(root: Path | Index, findings: list[dict]) -> list[dict]:
    """Annotate ``findings`` ({rule, path, line, source}) with reach state and chain."""
    index = root if isinstance(root, Index) else Index.from_root(root)
    summary: dict[str, dict[str, list[str]]] = {}
    seeds = _seed(index, findings, summary)
    propagation = _Propagation(index, _call_graph(index), summary)
    propagation.run()
    annotated = []
    for finding, seed in zip(findings, seeds):
        result = propagation.state(seed)
        annotated.append(
            {**finding, "reach": result.state, "reach_chain": result.chain}
        )
    return annotated


ENTRY_REACH_SCOPE = "source_bound_entry_reach"
REACH_CODES = {
    "SECURITY_OS_COMMAND",
    "SECURITY_SHELL_COMMAND",
    "SECURITY_SQL_INJECTION",
    "SECURITY_PATH_TRAVERSAL",
}
_INDEX_CACHE: dict[str, Index] = {}


def _local_assignments(func: Function) -> dict[str, list[ast.AST]]:
    assigned: dict[str, list[ast.AST]] = {}
    for node in ast.walk(func.node):
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)) and node.value:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    assigned.setdefault(target.id, []).append(node.value)
    return assigned


def _unsanitized_names(expr: ast.AST) -> list[str]:
    """Names in ``expr`` outside any sanitizer call."""
    if isinstance(expr, ast.Call) and _SANITIZERS.search(_dotted(expr.func)):
        return []
    if isinstance(expr, ast.Name):
        return [expr.id]
    return [
        n for child in ast.iter_child_nodes(expr) for n in _unsanitized_names(child)
    ]


def _sink_parameters(func: Function, line: int) -> list[str]:
    """Parameters that reach the first argument of the call at ``line``."""
    calls = [
        node
        for node in ast.walk(func.node)
        if isinstance(node, ast.Call) and node.lineno == line and node.args
    ]
    if not calls:
        return []
    assigned = _local_assignments(func)
    found, seen, pending = [], set(), [calls[0].args[0]]
    while pending:
        expr = pending.pop()
        if isinstance(expr, ast.Call) and _SANITIZERS.search(_dotted(expr.func)):
            continue
        names = _unsanitized_names(expr)
        for name in (n for n in names if n not in seen):
            seen.add(name)
            found.extend([name] if name in func.params else [])
            pending.extend(assigned.get(name, []))
    return found


def _source_index(source_bytes: dict, bindings: dict) -> Index:
    import hashlib

    key = hashlib.sha256(
        json.dumps(sorted(bindings.items()), separators=(",", ":")).encode()
    ).hexdigest()
    if key not in _INDEX_CACHE:
        texts = {
            path: data.decode("utf-8", errors="replace")
            for path, data in source_bytes.items()
            if isinstance(path, str) and isinstance(data, (bytes, bytearray))
        }
        _INDEX_CACHE.clear()
        _INDEX_CACHE[key] = Index(texts)
    return _INDEX_CACHE[key]


def entry_reach_tier(finding, source_bytes, bindings, decided):
    """Promote a command, SQL or path finding whose sink parameter an entry reaches.

    Only a ``NEEDS_CONTEXT`` decision changes; the reach chain becomes the
    evidence detail. The index is rebuilt from the captured source bytes, so an
    independent regeneration of the tier report reaches the same decision.
    """
    tier, evidence, details = decided
    path, line = finding.get("path"), finding.get("line")
    if (
        tier != "NEEDS_CONTEXT"
        or finding.get("code") not in REACH_CODES
        or not isinstance(source_bytes, dict)
        or path not in source_bytes
        or not isinstance(line, int)
    ):
        return decided
    index = _source_index(source_bytes, bindings if isinstance(bindings, dict) else {})
    func = index.enclosing(path, line)
    if func is None:
        return decided
    rows = [
        {"rule": finding["code"], "path": path, "line": line, "source": param}
        for param in _sink_parameters(func, line)
    ]
    for row in reach(index, rows):
        if row["reach"] == "entry_reached":
            detail = {
                "schema": REACH_SCHEMA,
                "parameter": row["source"],
                "chain": row["reach_chain"],
            }
            return "SUPPORTED_DEFECT", ENTRY_REACH_SCOPE, {"entry_reach": detail}
    return decided


def findings_from_opengrep(report: dict, prefix: str = "") -> list[dict]:
    """Parameter-rule findings from opengrep JSON run with ``--dataflow-traces``."""
    rows = []
    for result in report.get("results", []):
        rule = ".".join(result["check_id"].split(".")[-2:])
        if not rule.startswith("python.parameter-"):
            continue
        extra = result.get("extra", {})
        trace = extra.get("dataflow_trace") or {}
        source = trace.get("taint_source")
        name = source[1][1] if isinstance(source, list) and len(source) > 1 else None
        if name is None:
            # Search-mode rules bind the parameter as $P instead of a taint source.
            name = (extra.get("metavars", {}).get("$P") or {}).get("abstract_content")
        path = (
            result["path"][len(prefix) :].lstrip("/")
            if prefix and result["path"].startswith(prefix)
            else result["path"]
        )
        rows.append(
            {
                "rule": rule,
                "path": path,
                "line": result["start"]["line"],
                "source": name,
            }
        )
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factoryline.parameter_reach")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--opengrep-json", required=True, type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    report = json.loads(args.opengrep_json.read_text(encoding="utf-8"))
    rows = reach(root, findings_from_opengrep(report, str(root)))
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["reach"]] = counts.get(row["reach"], 0) + 1
    json.dump(
        {"schema": REACH_SCHEMA, "counts": counts, "findings": rows},
        sys.stdout,
        indent=2,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
