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

from dataclasses import dataclass
import re
from typing import Any


_PLACEHOLDER_RE = re.compile(r"\b(?:todo|tbd|n/?a|unknown|unspecified|fill\s+in|your\s+choice)\b|\?{2,}", re.I)
_VAGUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("make_it_better", re.compile(r"\bmake\s+(?:it|this)\s+better\b", re.I)),
    ("do_something", re.compile(r"\bdo\s+something\b", re.I)),
    ("as_needed", re.compile(r"\bas\s+needed\b|\bas\s+appropriate\b|\bas\s+necessary\b", re.I)),
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


def assess(value: Any, *, field: str, require_action: bool = True,
           require_observable: bool = False) -> tuple[str, list[IntentFinding]]:
    """Return normalized text and deterministic clarity findings.

    This function intentionally returns findings instead of deciding whether a
    mission is safe.  Callers map the findings to their own stable error type
    and retain their existing human/authority boundaries.
    """
    text = normalize(value)
    findings: list[IntentFinding] = []
    if _PLACEHOLDER_RE.search(text):
        findings.append(IntentFinding("INTENT_PLACEHOLDER", f"{field} contains a placeholder or unresolved value"))
    for name, pattern in _VAGUE_PATTERNS:
        if pattern.search(text):
            findings.append(IntentFinding("INTENT_VAGUE_LANGUAGE", f"{field} contains vague phrase: {name}"))
            break
    if require_action and not _ACTION_RE.search(text):
        findings.append(IntentFinding("INTENT_NO_ACTION", f"{field} does not state an observable action or state transition"))
    if require_observable and not _OBSERVABLE_RE.search(text):
        findings.append(IntentFinding("INTENT_NOT_OBSERVABLE", f"{field} does not name observable evidence or an outcome boundary"))
    return text, findings


def require_clear(value: Any, *, field: str, require_action: bool = True,
                  require_observable: bool = False) -> str:
    """Normalize and fail closed on the first clarity finding."""
    text, findings = assess(value, field=field, require_action=require_action, require_observable=require_observable)
    if findings:
        raise IntentQualityError(findings[0])
    return text


def findings_as_dict(value: Any, *, field: str, require_action: bool = True,
                    require_observable: bool = False) -> list[dict[str, str]]:
    """Expose stable findings for receipts and diagnostics without raising."""
    _text, findings = assess(value, field=field, require_action=require_action, require_observable=require_observable)
    return [finding.as_dict() for finding in findings]
