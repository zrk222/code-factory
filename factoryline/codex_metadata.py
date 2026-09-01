"""Deterministic integrity checks for Codex/workflow metadata.

Metadata is useful context, but it is not evidence merely because an agent
called it complete.  This module hashes selected local files, parses them
completely, and makes unbound or contradictory terminal claims visible.  It
never executes commands, contacts a provider, or grants authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "factory.codex-metadata-integrity.v1"
MAX_FILE_BYTES = 1_048_576
MAX_FILES = 256
DEFAULT_PATHS = ("context", "skills", "envelopes", ".forge")
SUPPORTED_SUFFIXES = frozenset({".json", ".jsonl", ".md", ".txt"})
TERMINAL_VALUES = frozenset({
    "success", "succeeded", "complete", "completed", "shipped", "published",
    "uploaded", "approved", "verified", "ready", "passed", "green", "live",
})
PROBLEM_VALUES = frozenset({
    "pending", "blocked", "partial", "failed", "failure", "unknown", "incomplete",
    "review_required", "needs_revision", "queued", "stalled",
})
STATE_KEYS = frozenset({"status", "state", "outcome", "result", "decision", "phase"})
EVIDENCE_KEYS = frozenset({
    "command", "commands", "artifact", "artifacts", "path", "paths", "sha256", "hash",
    "receipt", "receipts", "evidence", "readback", "read_back", "provider_receipt",
    "verification", "verified_at", "provider_url", "url", "run_id", "execution_id",
})
STRONG_EVIDENCE_KEYS = frozenset({
    "sha256", "hash", "receipt", "receipts", "readback", "read_back", "provider_receipt",
    "provider_url", "published_url", "verified_at", "artifact_digest",
})
NEGATIVE_PROOF_KEYS = frozenset({
    "mutation", "mutations", "hollow", "negative", "holdout", "counterexample", "challenge",
    "adversarial", "empty_implementation", "survival", "survival_card", "proof_of_failure",
})
PROVIDER_KEYS = frozenset({
    "provider", "provider_receipt", "provider_url", "readback", "read_back", "published_url",
    "marketplace", "pypi", "github", "openvsx", "jetbrains", "huggingface", "vscode",
})
IDENTITY_KEYS = frozenset({"agent", "author_agent", "created_by", "actor", "worker", "producer"})
VERIFIER_KEYS = frozenset({
    "verifier", "verifier_agent", "independent_verifier", "reviewer", "grader", "audit_agent",
})
INTENT_KEYS = frozenset({"intent", "intent_id", "intent_hash", "requirements", "acceptance_criteria", "spec"})
UNCLEAR_INTENT_VALUES = frozenset({"ambiguous", "unclear", "needs_clarification", "needs_review", "unknown"})
CONFIRMED_INTENT_VALUES = frozenset({"clear", "confirmed", "verified", "grilled", "accepted"})
GATE_KEYS = frozenset({
    "tests_passed", "test_passed", "gate_passed", "all_checks_passed", "all_green",
    "validators_passed", "verification_passed", "quality_gate", "ci_passed",
})
_PATH_KEYS = frozenset({"root", "workspace", "cwd", "checkout", "repository"})
_NON_EXECUTION_STATE_SEGMENTS = frozenset({"active_policy", "constraints", "policy", "policies"})
_PROVIDER_RE = re.compile(r"\b(?:pypi|github|open\s*vsx|jetbrains|hugging\s*face|visual\s*studio|provider|marketplace)\b", re.I)
_TERMINAL_RE = re.compile(r"\b(?:success(?:ful|fully)?|complete(?:d)?|shipped|publish(?:ed)?|upload(?:ed)?|approv(?:ed|al)|verif(?:ied|y)|ready|passed|green|live)\b", re.I)
_PROBLEM_RE = re.compile(r"\b(?:pending|blocked|partial|fail(?:ed|ure)?|unknown|incomplete|review[_ -]?required|needs[_ -]?revision|queued|stalled)\b", re.I)
_PROVIDER_COMPLETION_RE = re.compile(
    r"(?:\b(?:success(?:ful|fully)?|complete(?:d)?|shipped|publish(?:ed)?|upload(?:ed)?|"
    r"approv(?:ed|al)|verif(?:ied|y)|ready|passed|green|live)\b[^\n]{0,80}\b"
    r"(?:pypi|github|open\s*vsx|jetbrains|hugging\s*face|visual\s*studio|marketplace)\b|"
    r"\b(?:pypi|github|open\s*vsx|jetbrains|hugging\s*face|visual\s*studio|marketplace)\b[^\n]{0,80}\b"
    r"(?:success(?:ful|fully)?|complete(?:d)?|shipped|publish(?:ed)?|upload(?:ed)?|approv(?:ed|al)|"
    r"verif(?:ied|y)|ready|passed|green|live)\b|"
    r"\bprovider\s*[:=][^\n]{0,80}\b(?:status|state|outcome)\s*[:=][^\n]{0,40}\b"
    r"(?:success|complete|shipped|published|uploaded|approved|verified|ready|passed|green|live)\b)",
    re.I,
)


class MetadataAuditError(ValueError):
    """Stable fail-closed error for metadata input/output boundaries."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _relative(workspace: Path, supplied: Path, label: str) -> Path:
    base = workspace.resolve()
    candidate = supplied if supplied.is_absolute() else base / supplied
    resolved = candidate.resolve()
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise MetadataAuditError("E_METADATA_PATH_ESCAPE", f"{label} must remain inside the workspace") from exc
    return resolved


def _display(workspace: Path, path: Path) -> str:
    return path.resolve().relative_to(workspace.resolve()).as_posix()


def _walk_pairs(value: Any, prefix: str = "record") -> Iterable[tuple[str, str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            location = f"{prefix}.{key}"
            yield str(key).lower(), location, child
            yield from _walk_pairs(child, location)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_pairs(child, f"{prefix}[{index}]")


def _records(value: Any, prefix: str = "record") -> Iterable[tuple[str, dict[str, Any]]]:
    if isinstance(value, dict):
        yield prefix, value
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                yield from _records(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            if isinstance(child, (dict, list)):
                yield from _records(child, f"{prefix}[{index}]")


def _nonempty(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (dict, list, tuple, set)):
        return bool(value)
    return value is not None


def _is_execution_state_location(location: str) -> bool:
    """Reject policy labels and historical transitions as live-run evidence.

    A policy may be ``active`` indefinitely, and a historical state machine
    legitimately contains both ``blocked`` and ``shipped``.  Neither means a
    current process is running.  The current record is still audited for an
    unbound terminal claim; this narrow filter only prevents those passive
    labels from creating duplicated false ``E_METADATA_ORPHAN_ACTIVE`` or
    contradictory-status findings.
    """
    segments = {part.split("[", 1)[0].lower() for part in location.split(".")}
    return not bool(segments.intersection(_NON_EXECUTION_STATE_SEGMENTS | {"history"}))


def _anchors(record: dict[str, Any]) -> set[str]:
    anchors: set[str] = set()
    for key, _location, value in _walk_pairs(record):
        if key in EVIDENCE_KEYS and key not in {"evidence", "verification"} and _nonempty(value):
            anchors.add(key)
        if key in {"evidence", "verification", "receipt", "receipts", "provider_receipt"} and isinstance(value, (dict, list)):
            # A container is useful only when it contains a concrete anchor.
            continue
    return anchors


def _strong_anchors(record: dict[str, Any]) -> set[str]:
    return {
        key for key, _location, value in _walk_pairs(record)
        if key in STRONG_EVIDENCE_KEYS and _nonempty(value)
    }


def _provider_anchors(record: dict[str, Any]) -> set[str]:
    anchors: set[str] = set()
    for key, _location, value in _walk_pairs(record):
        # Merely naming a provider is not provider evidence.  A receipt, URL,
        # or explicit read-back is the load-bearing anchor.
        concrete = key in {"provider_receipt", "provider_url", "published_url", "readback", "read_back"} or ("provider" in key and key != "provider")
        if concrete and _nonempty(value):
            anchors.add(key)
    return anchors


def _has_provider_identity(record: dict[str, Any]) -> bool:
    """Detect a provider named as structured data, not merely in prose."""
    provider_names = {"pypi", "github", "openvsx", "jetbrains", "huggingface", "visualstudio", "marketplace"}
    for key, _location, value in _walk_pairs(record):
        if key == "provider" or key in provider_names:
            return True
        if isinstance(value, str):
            normalized = re.sub(r"[^a-z]", "", value.lower())
            if normalized in provider_names:
                return True
    return False


def _claim_values(record: dict[str, Any], prefix: str = "record") -> tuple[set[str], set[str], list[tuple[str, Any]]]:
    terminal: set[str] = set()
    problem: set[str] = set()
    gate_claims: list[tuple[str, Any]] = []
    for key, location, value in _walk_pairs(record, prefix):
        if key in STATE_KEYS and isinstance(value, str) and _is_execution_state_location(location):
            normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
            if normalized in TERMINAL_VALUES:
                terminal.add(location)
            if normalized in PROBLEM_VALUES:
                problem.add(location)
        if key == "verified" and value is True:
            terminal.add(location)
        if key in GATE_KEYS and value is True:
            terminal.add(location)
            gate_claims.append((location, value))
    return terminal, problem, gate_claims


def _has_independent_verifier(record: dict[str, Any]) -> bool:
    authors: set[str] = set()
    verifiers: set[str] = set()
    for key, _location, value in _walk_pairs(record):
        if key in IDENTITY_KEYS and isinstance(value, str) and value.strip():
            authors.add(value.strip().lower())
        if key in VERIFIER_KEYS and _nonempty(value):
            if isinstance(value, str):
                verifiers.add(value.strip().lower())
            else:
                verifiers.add("structured-verifier")
    return bool(verifiers) and not (authors and verifiers.intersection(authors))


def _intent_state(record: dict[str, Any]) -> tuple[bool, bool]:
    """Return (bound, explicitly_unclear) for a terminal record's user intent."""
    bound = False
    unclear = False
    for key, _location, value in _walk_pairs(record):
        if key == "intent_hash" and isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()):
            bound = True
        elif key in {"intent_id", "intent", "requirements", "acceptance_criteria", "spec"} and _nonempty(value):
            bound = True
        if key in {"intent_status", "intent_state"} and isinstance(value, str):
            normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
            unclear = unclear or normalized in UNCLEAR_INTENT_VALUES
            bound = bound or normalized in CONFIRMED_INTENT_VALUES
    return bound, unclear


def _path_mismatch(workspace: Path, record: dict[str, Any]) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for key, location, value in _walk_pairs(record):
        if key not in _PATH_KEYS or not isinstance(value, str) or not value.strip():
            continue
        candidate = Path(value.strip())
        if not candidate.is_absolute():
            continue
        try:
            candidate.resolve().relative_to(workspace.resolve())
        except ValueError:
            findings.append((location, value.strip()))
    return findings


def _finding(code: str, path: str, location: str, detail: str) -> dict[str, str]:
    return {"code": code, "path": path, "location": location, "detail": detail}


def _audit_record(workspace: Path, path: str, location: str, record: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    terminal, problem, gate_claims = _claim_values(record, location)
    anchors = _anchors(record)
    strong_anchors = _strong_anchors(record)
    provider_anchors = _provider_anchors(record)
    intent_bound, intent_unclear = _intent_state(record)
    if terminal and not anchors:
        findings.append(_finding("E_METADATA_UNBOUND_TERMINAL", path, location, "terminal claim has no command, artifact, receipt, read-back, or hash anchor"))
    elif terminal and not strong_anchors:
        findings.append(_finding("E_METADATA_WEAK_EVIDENCE", path, location, "terminal claim has only a command or path and no receipt, digest, timestamp, or read-back anchor"))
    if terminal and problem:
        findings.append(_finding("E_METADATA_CONTRADICTORY_STATUS", path, location, "terminal claim is combined with pending, blocked, partial, failed, or unknown state"))
    text = json.dumps(record, ensure_ascii=False, sort_keys=True).lower()
    if terminal and _has_provider_identity(record) and not provider_anchors:
        findings.append(_finding("E_METADATA_PROVIDER_UNBOUND", path, location, "provider completion claim lacks a provider receipt, URL, or read-back anchor"))
    if gate_claims and not _has_independent_verifier(record):
        findings.append(_finding("E_METADATA_SELF_ATTESTED_GATE", path, location, "test or gate success is self-attested; an independent verifier is absent or matches the author"))
    if gate_claims:
        negative = {key for key, _location, value in _walk_pairs(record) if key in NEGATIVE_PROOF_KEYS and _nonempty(value)}
        if not negative:
            findings.append(_finding("E_METADATA_GATE_NO_NEGATIVE_PROOF", path, location, "test or gate success has no mutation, holdout, counterexample, or adversarial proof"))
    if (terminal or gate_claims) and not intent_bound:
        findings.append(_finding("E_METADATA_INTENT_UNBOUND", path, location, "terminal or gate claim has no bound user intent id, hash, requirements, or confirmed intent"))
    if (terminal or gate_claims) and intent_unclear:
        findings.append(_finding("E_METADATA_INTENT_UNCLEAR", path, location, "terminal or gate claim is associated with ambiguous or needs-clarification intent"))
    for mismatch_location, supplied in _path_mismatch(workspace, record):
        findings.append(_finding("E_METADATA_WORKSPACE_MISMATCH", path, mismatch_location, f"absolute workspace path is outside selected workspace: {supplied}"))
    states = [
        value for key, state_location, value in _walk_pairs(record, location)
        if key in {"status", "state"} and isinstance(value, str) and _is_execution_state_location(state_location)
    ]
    if any(value.strip().lower() == "active" for value in states):
        execution_keys = {key for key, _location, value in _walk_pairs(record) if key in {"run_id", "execution_id", "started_at", "last_event", "execution"} and _nonempty(value)}
        if not execution_keys and not anchors:
            findings.append(_finding("E_METADATA_ORPHAN_ACTIVE", path, location, "active state has no execution identity or evidence"))
    return findings


def _audit_text(workspace: Path, path: str, text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        terminal = bool(_TERMINAL_RE.search(line))
        problem = bool(_PROBLEM_RE.search(line))
        evidence = bool(re.search(r"(?:sha256|receipt|artifact|command|read[ -]?back|https?://|evidence)", line, re.I))
        strong_evidence = bool(re.search(r"(?:sha256|receipt|read[ -]?back|https?://|verified[_ -]?at|digest)", line, re.I))
        location = f"line:{number}"
        if terminal and not evidence:
            findings.append(_finding("E_METADATA_UNBOUND_TERMINAL", path, location, "terminal prose claim has no visible evidence anchor"))
        elif terminal and not strong_evidence:
            findings.append(_finding("E_METADATA_WEAK_EVIDENCE", path, location, "terminal prose claim has no receipt, digest, timestamp, or read-back anchor"))
        if terminal and problem:
            findings.append(_finding("E_METADATA_CONTRADICTORY_STATUS", path, location, "terminal prose claim is combined with a problem state"))
        if _PROVIDER_COMPLETION_RE.search(line) and not re.search(r"(?:provider[_ -]?receipt|read[ -]?back|https?://|url|sha256)", line, re.I):
            findings.append(_finding("E_METADATA_PROVIDER_UNBOUND", path, location, "provider completion prose has no provider receipt, URL, or read-back anchor"))
        if re.search(r"\b(?:status|state)\s*[:=]\s*active\b", line, re.I) and not re.search(r"(?:run[_ -]?id|execution|started|last[_ -]?event|receipt|evidence)", line, re.I):
            findings.append(_finding("E_METADATA_ORPHAN_ACTIVE", path, location, "active prose state has no execution identity or evidence"))
        if re.search(r"(?:tests?[_ -]?passed|all[_ -]?green|gate[_ -]?passed)\s*[:=]\s*(?:true|yes|pass(?:ed)?)", line, re.I) and not re.search(r"(?:verifier|reviewer|grader|independent)", line, re.I):
            findings.append(_finding("E_METADATA_SELF_ATTESTED_GATE", path, location, "test or gate success prose names no independent verifier"))
        if re.search(r"(?:tests?[_ -]?passed|all[_ -]?green|gate[_ -]?passed)\s*[:=]\s*(?:true|yes|pass(?:ed)?)", line, re.I) and not re.search(r"(?:mutation|hollow|negative|holdout|counterexample|challenge|adversarial|empty[_ -]?implementation|survival)", line, re.I):
            findings.append(_finding("E_METADATA_GATE_NO_NEGATIVE_PROOF", path, location, "test or gate success prose has no negative or adversarial proof"))
        if (terminal or re.search(r"(?:tests?[_ -]?passed|all[_ -]?green|gate[_ -]?passed)\s*[:=]\s*(?:true|yes|pass(?:ed)?)", line, re.I)) and not re.search(r"(?:intent(?:[_ -]?(?:id|hash|status|state))?|requirements?|acceptance|spec)", line, re.I):
            findings.append(_finding("E_METADATA_INTENT_UNBOUND", path, location, "terminal or gate prose has no bound user intent"))
        if re.search(r"(?:intent[_ -]?(?:status|state))\s*[:=]\s*(?:ambiguous|unclear|needs[_ -]?clarification|unknown)", line, re.I):
            findings.append(_finding("E_METADATA_INTENT_UNCLEAR", path, location, "intent is ambiguous or needs clarification"))
        if re.search(r"(?:workspace|cwd|checkout|repository)\s*[:=]\s*[A-Za-z]:[\\/]", line, re.I):
            supplied = re.split(r"[:=]", line, maxsplit=1)[-1].strip()
            try:
                Path(supplied).resolve().relative_to(workspace.resolve())
            except ValueError:
                findings.append(_finding("E_METADATA_WORKSPACE_MISMATCH", path, location, f"absolute workspace path is outside selected workspace: {supplied}"))
    return findings


def _discover(workspace: Path, paths: list[Path] | None) -> tuple[list[Path], list[dict[str, str]]]:
    requested = paths if paths else [Path(item) for item in DEFAULT_PATHS if (workspace / item).exists()]
    if not requested:
        raise MetadataAuditError("E_METADATA_INPUT_MISSING", "no metadata paths were selected or found")
    files: list[Path] = []
    findings: list[dict[str, str]] = []
    for supplied in requested:
        target = _relative(workspace, supplied, "metadata path")
        if not target.exists():
            raise MetadataAuditError("E_METADATA_INPUT_MISSING", f"metadata path does not exist: {supplied}")
        candidates = [target] if target.is_file() else sorted(item for item in target.rglob("*") if item.is_file())
        for candidate in candidates:
            resolved = candidate.resolve()
            try:
                resolved.relative_to(workspace.resolve())
            except ValueError:
                findings.append(_finding("E_METADATA_PATH_ESCAPE", _display(workspace, candidate), "file", "symlink or path resolves outside workspace"))
                continue
            files.append(resolved)
    files = sorted(set(files), key=lambda item: _display(workspace, item))
    if len(files) > MAX_FILES:
        raise MetadataAuditError("E_METADATA_TOO_MANY_FILES", f"metadata inventory exceeds {MAX_FILES} files")
    return files, findings


def audit_metadata(root: Path, paths: list[Path] | None = None) -> dict[str, Any]:
    """Audit selected local Codex metadata without executing or mutating it."""
    workspace = Path(root).resolve()
    files, findings = _discover(workspace, paths)
    inspected: list[dict[str, Any]] = []
    for path in files:
        relative = _display(workspace, path)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            findings.append(_finding("E_METADATA_INPUT_INVALID", relative, "file", f"unable to read metadata: {exc}"))
            continue
        digest = hashlib.sha256(raw).hexdigest()
        entry: dict[str, Any] = {"path": relative, "bytes": len(raw), "sha256": digest}
        if len(raw) > MAX_FILE_BYTES:
            findings.append(_finding("E_METADATA_TOO_LARGE", relative, "file", f"metadata file exceeds {MAX_FILE_BYTES} bytes"))
            entry["format"] = "oversize"
            inspected.append(entry)
            continue
        suffix = path.suffix.lower()
        entry["format"] = suffix.lstrip(".") or "none"
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            findings.append(_finding("E_METADATA_INPUT_INVALID", relative, "file", f"metadata is not UTF-8: {exc}"))
            inspected.append(entry)
            continue
        if suffix not in SUPPORTED_SUFFIXES:
            findings.append(_finding("E_METADATA_FORMAT_UNSUPPORTED", relative, "file", f"unsupported metadata format: {suffix or '<none>'}"))
            inspected.append(entry)
            continue
        if suffix == ".json":
            try:
                value = json.loads(text)
            except json.JSONDecodeError as exc:
                findings.append(_finding("E_METADATA_PARSE_INVALID", relative, f"line:{exc.lineno}", f"invalid JSON: {exc.msg}"))
            else:
                records = list(_records(value))
                entry["records"] = len(records)
                for location, record in records:
                    findings.extend(_audit_record(workspace, relative, location, record))
        elif suffix == ".jsonl":
            records = 0
            for number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    findings.append(_finding("E_METADATA_PARSE_INVALID", relative, f"line:{number}", f"invalid JSONL record: {exc.msg}"))
                    continue
                for location, record in _records(value, f"line:{number}"):
                    records += 1
                    findings.extend(_audit_record(workspace, relative, location, record))
            entry["records"] = records
        else:
            findings.extend(_audit_text(workspace, relative, text))
        inspected.append(entry)
    findings = sorted(findings, key=lambda item: (item["path"], item["location"], item["code"], item["detail"]))
    body: dict[str, Any] = {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "files": inspected,
        "findings": findings,
        "status": "REVIEW_REQUIRED" if findings else "VERIFIED",
        "markers": ["CODEX_METADATA_INPUT_ACCEPTED", "CODEX_METADATA_HASHED", "CODEX_METADATA_CLAIMS_CHECKED"],
        "authority": {"execute": False, "merge": False, "deploy": False, "release": False, "publish": False, "billing": False},
        "claim_boundary": "local metadata integrity only; this audit does not verify provider state, production readiness, or grant authority",
    }
    if findings:
        body["markers"].append("CODEX_METADATA_REVIEW_REQUIRED")
    body["audit_sha256"] = _sha({key: value for key, value in body.items() if key != "audit_sha256"})
    return body


def write_metadata_audit(root: Path, paths: list[Path] | None = None, out: Path | None = None) -> dict[str, Any]:
    """Audit metadata and optionally write one workspace-contained JSON receipt atomically."""
    workspace = Path(root).resolve()
    result = audit_metadata(workspace, paths)
    if out is None:
        return result
    destination = _relative(workspace, Path(out), "metadata output")
    destination.parent.mkdir(parents=True, exist_ok=True)
    final = {**result, "marker": "CODEX_METADATA_CLI_WRITTEN", "markers": [*result["markers"], "CODEX_METADATA_CLI_WRITTEN"], "path": _display(workspace, destination)}
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    try:
        temporary.write_text(json.dumps(final, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(destination)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise MetadataAuditError("E_METADATA_OUTPUT", f"unable to write metadata audit: {exc}") from exc
    return final
