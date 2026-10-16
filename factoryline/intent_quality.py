"""Deterministic quality checks for natural-language intent boundaries.

AI-authored text is untrusted input even when it appears in a signed or
hash-bound artifact.  A digest proves that text was not changed after it was
captured; it does not prove that the text was specific enough to test.  This
module supplies a small, dependency-free lexical guard for the places where
FactoryLine accepts intent, promises, requirements, or acceptance evidence.

The guard is deliberately conservative and explainable.  It does not infer a
product meaning or call a model.  It only rejects known placeholders/vague
phrases and statements that lack an action or (when requested) an observable
evidence signal.  A human still owns confirmation and an independent verifier
still owns the result.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Any


_PLACEHOLDER_RE = re.compile(
    r"\b(?:todo|tbd|n/?a|unknown|unspecified|fill\s+in|your\s+choice)\b|\?{2,}", re.I
)
_VAGUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("make_it_better", re.compile(r"\bmake\s+(?:it|this)\s+better\b", re.I)),
    ("do_something", re.compile(r"\bdo\s+something\b", re.I)),
    (
        "as_needed",
        re.compile(r"\bas\s+needed\b|\bas\s+appropriate\b|\bas\s+necessary\b", re.I),
    ),
    ("works", re.compile(r"\b(?:it|this|that)\s+works\b|\bshould\s+work\b", re.I)),
    ("fix_it", re.compile(r"\bfix\s+(?:it|this|that)\b", re.I)),
    ("etcetera", re.compile(r"\betc\.?\b|\band\s+so\s+on\b", re.I)),
    ("whatever", re.compile(r"\bwhatever\b|\banyhow\b", re.I)),
    ("stuff", re.compile(r"\bstuff\b|\bsomething\s+like\s+that\b", re.I)),
)

# These are deliberately words, not a parser.  They identify an action or a
# state transition without claiming that the sentence is semantically true.
_ACTION_RE = re.compile(
    r"\b(?:allow|approve|assert|block|build|call|capture|change|check|consume|"
    r"contain|create|delete|deny|detect|disable|display|emit|enable|equal|"
    r"fail|fetch|finish|generate|has|have|is|are|keep|list|measure|migrate|"
    r"must|never|notify|open|pass|prevent|produce|publish|record|reject|"
    r"release|remove|report|respond|return|run|save|show|start|stop|store|"
    r"succeed|succeeds|test|tests|update|updates|use|uses|validate|validates|"
    r"verify|verifies|visible|write|writes|work|works|fail|fails|reject|rejects|"
    r"record|records|recorded|produce|produces|receive|receives|receiving|"
    r"duplicate|release|releases|approve|approves|approval|run|runs|can|cannot|shall|will)\b",
    re.I,
)
_OBSERVABLE_RE = re.compile(
    r"\b(?:accept(?:ed|ance)?|actual|artifact|assert(?:ion)?|bound|check|"
    r"code|count|digest|error|event|exit|fail(?:ed|ure)?|file|hash|latency|"
    r"metric|output|pass(?:ed)?|proof|receipt|record(?:ed|ing|s)?|response|result|status|"
    r"timestamp|url|visible|within|under|over|equals?|contains?|rejected|"
    r"denied|created|updated|deleted|approved|approve|approval|rejected|visible)\b|sha-?256|given/when/then|\b\d+\b",
    re.I,
)


@dataclass(frozen=True)
class IntentFinding:
    """One deterministic reason a statement should not cross a gate."""

    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        """Return the stable code and human-readable explanation for a receipt."""
        return {"code": self.code, "message": self.message}


class IntentQualityError(ValueError):
    """Raised when a statement is too vague to bind to a proof gate."""

    def __init__(self, finding: IntentFinding):
        super().__init__(f"{finding.code}: {finding.message}")
        self.code = finding.code
        self.message = finding.message


def normalize(value: Any) -> str:
    """Normalize whitespace without changing the author's words."""
    return " ".join(value.split()) if isinstance(value, str) else ""


def assess(
    value: Any,
    *,
    field: str,
    require_action: bool = True,
    require_observable: bool = False,
) -> tuple[str, list[IntentFinding]]:
    """Return normalized text and deterministic clarity findings.

    This function intentionally returns findings instead of deciding whether a
    mission is safe.  Callers map the findings to their own stable error type
    and retain their existing human/authority boundaries.
    """
    text = normalize(value)
    findings: list[IntentFinding] = []
    if _PLACEHOLDER_RE.search(text):
        findings.append(
            IntentFinding(
                "INTENT_PLACEHOLDER",
                f"{field} contains a placeholder or unresolved value",
            )
        )
    for name, pattern in _VAGUE_PATTERNS:
        if pattern.search(text):
            findings.append(
                IntentFinding(
                    "INTENT_VAGUE_LANGUAGE", f"{field} contains vague phrase: {name}"
                )
            )
            break
    if require_action and not _ACTION_RE.search(text):
        findings.append(
            IntentFinding(
                "INTENT_NO_ACTION",
                f"{field} does not state an observable action or state transition",
            )
        )
    if require_observable and not _OBSERVABLE_RE.search(text):
        findings.append(
            IntentFinding(
                "INTENT_NOT_OBSERVABLE",
                f"{field} does not name observable evidence or an outcome boundary",
            )
        )
    return text, findings


def require_clear(
    value: Any,
    *,
    field: str,
    require_action: bool = True,
    require_observable: bool = False,
) -> str:
    """Normalize and fail closed on the first clarity finding."""
    text, findings = assess(
        value,
        field=field,
        require_action=require_action,
        require_observable=require_observable,
    )
    if findings:
        raise IntentQualityError(findings[0])
    return text


def findings_as_dict(
    value: Any,
    *,
    field: str,
    require_action: bool = True,
    require_observable: bool = False,
) -> list[dict[str, str]]:
    """Expose stable findings for receipts and diagnostics without raising."""
    _text, findings = assess(
        value,
        field=field,
        require_action=require_action,
        require_observable=require_observable,
    )
    return [finding.as_dict() for finding in findings]


# Static source contracts supplement the natural-language boundary checks.
def intentional_implementation_contract(node, parents, aliases):
    """Recognize explicit container or locally evidenced extension contracts."""
    return (
        click_group_container(node, parents, aliases)
        or _method_contract(node, parents)
        or _null_io_contract(node, parents, aliases)
    )


def _null_io_contract(node, parents, aliases):
    """Recognize an inert IO implementation by its complete local behavior.

    Neither the class name nor an isolated pass/zero return is sufficient.
    """
    owner = parents.get(node)
    if not isinstance(owner, ast.ClassDef) or owner.decorator_list:
        return False
    if node.decorator_list or not _stable_api_origin(
        owner, parents, aliases, {"typing", "typing.IO"}
    ):
        return False
    if node.name not in {"close", "flush", "writelines", "__exit__"}:
        return False
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    if len(body) != 1 or not isinstance(body[0], ast.Pass):
        return False
    bases = [
        base.value if isinstance(base, ast.Subscript) else base for base in owner.bases
    ]
    if len(bases) != 1 or not _typing_io_base(bases[0], aliases):
        return False
    methods = [n for n in owner.body if isinstance(n, ast.FunctionDef)]
    names = {n.name: n for n in methods}
    if len(names) != len(methods) or "__init__" in names:
        return False
    if any(
        isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del))
        for n in ast.walk(owner)
    ):
        return False
    required = {
        "readable": False,
        "writable": False,
        "seekable": False,
        "read": "",
        "readline": "",
        "write": 0,
    }
    return all(
        _literal_method(names.get(name), value) for name, value in required.items()
    )


def _typing_io_base(base, aliases):
    if isinstance(base, ast.Name):
        return aliases.get(base.id) == "typing.IO"
    return (
        isinstance(base, ast.Attribute)
        and base.attr == "IO"
        and isinstance(base.value, ast.Name)
        and aliases.get(base.value.id) == "typing"
    )


def _literal_method(node, expected):
    if node is None or node.decorator_list:
        return False
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    return (
        len(body) == 1
        and isinstance(body[0], ast.Return)
        and isinstance(body[0].value, ast.Constant)
        and type(body[0].value.value) is type(expected)
        and body[0].value.value == expected
    )


def _method_contract(node, parents):
    owner = parents.get(node)
    if not isinstance(owner, ast.ClassDef):
        return False
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    if len(body) != 1:
        return False
    documentation = " ".join((ast.get_docstring(node) or "").lower().split())
    if isinstance(body[0], ast.Pass):
        return "nothing by default" in documentation and "overrid" in documentation
    if not isinstance(body[0], ast.Raise):
        return False
    error = body[0].exc
    error = error.func if isinstance(error, ast.Call) else error
    if not isinstance(error, ast.Name) or error.id != "NotImplementedError":
        return False
    scope = parents.get(owner)
    if (
        not isinstance(scope, ast.Module)
        or _shadowed_error(scope)
        or owner.decorator_list
    ):
        return False
    if any(
        isinstance(item, ast.Call)
        and isinstance(item.func, ast.Name)
        and item.func.id == owner.name
        for item in ast.walk(scope)
    ):
        return False
    if "subclasses must override" in documentation or (
        "must be implemented" in documentation and "subclasses" in documentation
    ):
        return True
    return _local_override(owner, node.name, scope)


def _shadowed_error(scope):
    return any(
        (
            isinstance(item, ast.Name)
            and isinstance(item.ctx, (ast.Store, ast.Del))
            and item.id == "NotImplementedError"
        )
        or (
            isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and item.name == "NotImplementedError"
        )
        or (
            isinstance(item, ast.alias)
            and (item.asname or item.name.split(".")[0]) == "NotImplementedError"
        )
        or (isinstance(item, ast.arg) and item.arg == "NotImplementedError")
        for item in ast.walk(scope)
    )


def _local_override(owner, method, scope):
    # Require an unambiguous local base binding and a non-stub override.
    if (
        sum(isinstance(n, ast.ClassDef) and n.name == owner.name for n in scope.body)
        != 1
    ):
        return False
    if any(
        isinstance(n, ast.Name)
        and isinstance(n.ctx, (ast.Store, ast.Del))
        and n.id == owner.name
        for n in ast.walk(scope)
    ):
        return False
    return any(
        isinstance(child, ast.ClassDef)
        and any(
            isinstance(base, ast.Name) and base.id == owner.name for base in child.bases
        )
        and any(
            isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
            and function.name == method
            and _concrete_contract_method(function)
            for function in child.body
        )
        for child in scope.body
    )


def click_group_container(node, parents, aliases):
    """Recognize a default Click group with a statically registered child.

    This proves a container role, not that callbacks execute or commands work.
    Custom group implementations and invocation modes remain unverified.
    """
    if not node.decorator_list:
        return False
    if not _stable_api_origin(node, parents, aliases, {"click", "click.group"}):
        return False
    scope = parents.get(node)
    if not isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    definitions = {
        item.name: item
        for item in scope.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if not _stable_scope(scope, {node.name, *aliases, *definitions}, definitions):
        return False
    if not _recognized_group(node, definitions, aliases, set()):
        return False
    return any(
        isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and isinstance(decorator.func.value, ast.Name)
        and decorator.func.value.id == node.name
        and decorator.func.attr in {"command", "group"}
        for function in definitions.values()
        if function is not node
        for decorator in function.decorator_list
    )


def _stable_scope(scope, names, definitions):
    # A redefinition or assignment makes decorator ownership ambiguous.
    for statement in scope.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if (
                statement.name in names
                and definitions.get(statement.name) is not statement
            ):
                return False
            continue
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            continue
        if any(
            isinstance(item, (ast.Name, ast.Attribute))
            and isinstance(item.ctx, (ast.Store, ast.Del))
            and (
                item.id
                if isinstance(item, ast.Name)
                else ast.unparse(item).split(".")[0]
            )
            in names
            for item in ast.walk(statement)
        ):
            return False
    return True


def _recognized_group(function, definitions, aliases, visiting):
    if function.name in visiting or len(function.decorator_list) != 1:
        return False
    visiting = visiting | {function.name}
    return any(
        _group_decorator(d, definitions, aliases, visiting)
        for d in function.decorator_list
    )


def _group_decorator(decorator, definitions, aliases, visiting):
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(decorator, ast.Call) and (
        decorator.args
        or any(
            keyword.arg not in {"help", "short_help"}
            or not isinstance(keyword.value, ast.Constant)
            or not isinstance(keyword.value.value, str)
            for keyword in decorator.keywords
        )
    ):
        return False
    if isinstance(target, ast.Name):
        return aliases.get(target.id) == "click.group"
    if not isinstance(target, ast.Attribute) or target.attr != "group":
        return False
    if not isinstance(target.value, ast.Name):
        return False
    owner = target.value.id
    if aliases.get(owner) == "click":
        return True
    return owner in definitions and _recognized_group(
        definitions[owner], definitions, aliases, visiting
    )


def implementation_findings(relative, tree, data, context):
    """Apply project contracts only to empty-body findings, never other rules."""
    from .review_integrity import implementation_completeness_findings

    lines = (context or {}).get("implementation_contract_lines", ())
    return [
        f
        for f in implementation_completeness_findings(relative, tree, data)
        if f["code"] != "QUALITY_EMPTY_IMPLEMENTATION" or f["line"] not in lines
    ]


def project_contract_helpers():
    """Include every contract resolver in process-local cache identity."""
    return (
        bind_project_contracts,
        _bind_imported_base,
        _stable_import_contract,
        _declared_stub_method,
        _concrete_contract_method,
        _shadowed_error,
        _stable_base_contract,
        _contract_body_nodes,
        _placeholder_statement,
        _unsafe_project_bases,
        bound_snapshots,
        _BoundSourceBytes.get,
        _BoundSourceBytes.__init__,
    )


def bind_project_contracts(root, snapshots, contexts, edges):
    """Resolve direct local imported bases from the already hash-bound snapshots."""
    from .review_audits import _oracle_imports

    eligible = {p.resolve(): p for p in snapshots}
    resolved = {
        path: _oracle_imports(root, path, tree, eligible)
        for path, tree in snapshots.items()
    }
    blocked = _unsafe_project_bases(snapshots, resolved)
    for path, tree in snapshots.items():
        imports = resolved[path]
        for child in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            if child.decorator_list:
                continue
            for base in child.bases:
                if not isinstance(base, ast.Name) or base.id not in imports:
                    continue
                if not _stable_import_contract(tree, base.id, child.lineno):
                    continue
                source, symbol = imports[base.id]
                if (
                    symbol is not None
                    and source in snapshots
                    and (source, symbol) not in blocked
                ):
                    _bind_imported_base(
                        root,
                        path,
                        child,
                        source,
                        symbol,
                        snapshots[source],
                        contexts,
                        edges,
                    )


def _bind_imported_base(root, path, child, source, symbol, tree, contexts, edges):
    bases = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == symbol]
    if len(bases) != 1 or bases[0].decorator_list or _shadowed_error(tree):
        return
    if not _stable_base_contract(tree, bases[0]):
        return
    if any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == symbol
        for n in ast.walk(tree)
    ):
        return
    if any(
        isinstance(n, ast.Name)
        and isinstance(n.ctx, (ast.Store, ast.Del))
        and n.id == symbol
        for n in ast.walk(tree)
    ):
        return
    methods = {
        n.name: n
        for n in child.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for method in bases[0].body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        override = methods.get(method.name)
        if not _declared_stub_method(method) or not _concrete_contract_method(override):
            continue
        if type(method) is not type(override):
            continue
        contexts[source].setdefault("implementation_contract_lines", set()).add(
            method.lineno
        )
        edges.append(
            {
                "caller": path.relative_to(root).as_posix(),
                "target": source.relative_to(root).as_posix(),
                "kind": "implementation_contract",
                "symbol": symbol + "." + method.name,
                "strength": "declared_override",
            }
        )


def _stable_import_contract(tree, local, before):
    imports = [
        statement.lineno
        for statement in tree.body
        if isinstance(statement, (ast.Import, ast.ImportFrom))
        for alias in statement.names
        if (alias.asname or alias.name.split(".")[0]) == local
    ]
    if len(imports) != 1 or imports[0] >= before:
        return False
    return not any(
        (
            isinstance(n, ast.Name)
            and isinstance(n.ctx, (ast.Store, ast.Del))
            and n.id == local
        )
        or (
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and n.name == local
        )
        or (
            isinstance(n, ast.Attribute)
            and isinstance(n.ctx, (ast.Store, ast.Del))
            and isinstance(n.value, ast.Name)
            and n.value.id == local
        )
        or (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == local
        )
        for n in ast.walk(tree)
    )


def _stable_base_contract(tree, owner):
    return not any(
        (
            isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == owner.name
            and node is not owner
        )
        or (
            isinstance(node, ast.alias)
            and (node.asname or node.name.split(".")[0]) == owner.name
        )
        for node in ast.walk(tree)
    )


def _declared_stub_method(node):
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    if len(body) != 1:
        return False
    statement = body[0]
    if isinstance(statement, ast.Raise):
        error = (
            statement.exc.func if isinstance(statement.exc, ast.Call) else statement.exc
        )
        return isinstance(error, ast.Name) and error.id == "NotImplementedError"
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and statement.value.value is Ellipsis
        and node.returns is not None
    )


def _concrete_contract_method(node):
    if node is None or node.decorator_list:
        return False
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    if not body or _declared_stub_method(node):
        return False
    nodes = list(_contract_body_nodes(body))
    if any(_placeholder_statement(n) for n in nodes):
        return False
    return any(
        isinstance(n, (ast.Return, ast.Assign, ast.AnnAssign))
        or (isinstance(n, ast.Expr) and isinstance(n.value, (ast.Call, ast.Await)))
        for n in nodes
    )


def _contract_body_nodes(statements):
    for statement in statements:
        if isinstance(
            statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        yield statement
        yield from _contract_body_nodes(ast.iter_child_nodes(statement))


def _placeholder_statement(node):
    if isinstance(node, ast.Raise):
        error = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
        return isinstance(error, ast.Name) and error.id == "NotImplementedError"
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and node.value.value is Ellipsis
    )


def _stable_api_origin(node, parents, aliases, targets):
    roots = {name for name, target in aliases.items() if target in targets}
    if not roots:
        return False
    scopes = []
    parent = parents.get(node)
    while parent is not None:
        if isinstance(
            parent, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            scopes.append(parent)
        parent = parents.get(parent)
    for name in roots:
        imports = [
            statement
            for scope in scopes
            for statement in scope.body
            if isinstance(statement, (ast.Import, ast.ImportFrom))
            for alias in statement.names
            if (alias.asname or alias.name.split(".")[0]) == name
        ]
        if len(imports) != 1 or imports[0].lineno >= node.lineno:
            return False
    return not any(
        isinstance(item, ast.Attribute)
        and isinstance(item.ctx, (ast.Store, ast.Del))
        and ast.unparse(item).split(".")[0] in roots
        for scope in scopes
        for item in ast.walk(scope)
    )


def _unsafe_project_bases(snapshots, resolved):
    blocked = set()
    for path, tree in snapshots.items():
        for local, (source, symbol) in resolved[path].items():
            if symbol is not None:
                if not _stable_import_contract(tree, local, float("inf")):
                    blocked.add((source, symbol))
                continue
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == local
                ):
                    blocked.add((source, node.func.attr))
    return blocked


class _BoundSourceBytes:
    def __init__(self, root, data, bindings):
        self.root, self.data = root, data
        self.expected = {row["path"]: row["sha256"] for row in bindings}

    def get(self, path):
        from .review_audits import _security_source_bytes, ReviewAuditError, MAX_BYTES
        from .runtime_audit_common import RuntimeAuditError
        from .deep_audit_io import local_file

        relative = path.relative_to(self.root).as_posix()
        expected = self.expected.get(relative)
        if expected is None:
            raise RuntimeAuditError("Snapshot has no original source identity")
        data = self.data.get(path)
        if data is None:
            if (
                path.is_symlink()
                or local_file(self.root, relative).stat().st_size > MAX_BYTES
            ):
                raise RuntimeAuditError("Snapshot exceeds source boundary")
            data = _security_source_bytes(self.root, relative)
        if len(data) > MAX_BYTES or sha256(data).hexdigest() != expected:
            raise ReviewAuditError(
                "Source changed before snapshot parsing: " + relative
            )
        return data


def bound_snapshots(root, files, data, bindings):
    from .review_audits import _oracle_snapshots

    return _oracle_snapshots(root, files, _BoundSourceBytes(root, data, bindings))
