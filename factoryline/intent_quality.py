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
    return click_group_container(node, parents, aliases) or _method_contract(
        node, parents
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
            and any(
                isinstance(
                    statement,
                    (
                        ast.Return,
                        ast.Assign,
                        ast.AnnAssign,
                        ast.With,
                        ast.AsyncWith,
                        ast.For,
                        ast.AsyncFor,
                        ast.If,
                        ast.Try,
                    ),
                )
                for statement in function.body
            )
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
