"""Source-bound intent and framework intake before a Product Mission begins.

This module deliberately separates *asking for a decision* from *making one*.
It derives a small, deterministic framework shortlist from declared PRD terms,
then requires a named human to select the framework, state the intent, define
acceptance evidence, and declare the external-effects boundary.  The resulting
confirmation is immutable and can be bound to a Product Graph and Mission.

It does not call a model, generate code, create a mission, or grant execution
authority.  A keyword shortlist is a review aid, not architectural advice.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .product_missions import ProductMissionError, analyze_product_text
from .intent_quality import IntentQualityError, require_clear


INTAKE_GRILL_SCHEMA = "factory.intake-grill.v1"
INTAKE_CONFIRMATION_SCHEMA = "factory.intake-confirmation.v1"
MAX_SOURCE_BYTES = 65_536
MAX_TEXT = 1_000
_SHA = re.compile(r"^[a-f0-9]{64}$")
_PROJECT = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
_SECRET = re.compile(r"(?:\b(?:sk|pk|ghp|github_pat|xox[baprs]|AIza)[_-][A-Za-z0-9_-]{12,}|-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----)", re.I)
_AUTHORITY = {
    "implementation": "not_authorized",
    "execution": "not_authorized",
    "external_effects": "not_authorized",
    "publication": "not_authorized",
    "deployment": "not_authorized",
}
_EXTERNAL_EFFECTS = frozenset({"local_only", "human_controlled"})

# The order is stable so the receipt stays reproducible for unchanged input.
_FRAMEWORKS: tuple[dict[str, Any], ...] = (
    {
        "id": "jetbrains-plugin",
        "label": "JetBrains plugin",
        "signals": ("jetbrains", "intellij", "pycharm", "rider", "webstorm", "plugin"),
        "use_when": "The declared primary surface is a JetBrains IDE integration.",
    },
    {
        "id": "vscode-extension",
        "label": "VS Code extension",
        "signals": ("vscode", "vs code", "visual studio code", "extension"),
        "use_when": "The declared primary surface is a VS Code integration.",
    },
    {
        "id": "langgraph-flow",
        "label": "LangGraph flow adapter",
        "signals": ("langgraph", "checkpoint", "agent graph", "state graph", "durable graph"),
        "use_when": "The declared core is a durable, checkpointed agent workflow.",
    },
    {
        "id": "python-service",
        "label": "Python service or CLI",
        "signals": ("python", "fastapi", "pydantic", "cli", "command line"),
        "use_when": "The declared runtime is Python, a local CLI, or a Python API service.",
    },
    {
        "id": "typescript-web-service",
        "label": "TypeScript web service",
        "signals": ("typescript", "javascript", "next.js", "nextjs", "react", "node", "web app"),
        "use_when": "The declared primary surface is a TypeScript or browser application.",
    },
    {
        "id": "integration-adapter",
        "label": "Controlled integration adapter",
        "signals": ("slack", "notion", "webhook", "api", "connector", "integration"),
        "use_when": "The declared primary job is an integration with an external system.",
    },
    {
        "id": "custom",
        "label": "Custom / undecided",
        "signals": (),
        "use_when": "No listed surface fits, or a human has not made the framework decision yet.",
    },
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _project_id(value: str) -> str:
    lowered = value.strip().lower()
    if not _PROJECT.fullmatch(lowered):
        raise ProductMissionError("INTAKE_PROJECT_INVALID", "project must be 1-80 lowercase letters, digits, or hyphens")
    return lowered


def _relative(root: Path, value: Path | str, field: str, *, exists: bool = True) -> tuple[Path, str]:
    raw = Path(value)
    path = raw.resolve() if raw.is_absolute() else (root / raw).resolve()
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise ProductMissionError("INTAKE_PATH_OUTSIDE_ROOT", f"{field} must stay inside the workspace") from exc
    if not relative or "\x00" in relative or len(relative) > 512:
        raise ProductMissionError("INTAKE_PATH_INVALID", f"{field} path is invalid")
    if exists and not path.is_file():
        raise ProductMissionError("INTAKE_SOURCE_NOT_FOUND", f"{field} must name a readable file")
    return path, relative


def _read_prd(root: Path, value: Path | str) -> tuple[Path, str, bytes]:
    path, relative = _relative(root, value, "prd")
    try:
        source = path.read_bytes()
        source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProductMissionError("INTAKE_PRD_ENCODING_INVALID", "PRD must be valid UTF-8") from exc
    except OSError as exc:
        raise ProductMissionError("INTAKE_SOURCE_NOT_FOUND", "PRD cannot be read") from exc
    if not source or len(source) > MAX_SOURCE_BYTES:
        raise ProductMissionError("INTAKE_PRD_SIZE_INVALID", f"PRD must be 1-{MAX_SOURCE_BYTES} UTF-8 bytes")
    return path, relative, source


def _atomic_write(path: Path, data: bytes, *, force: bool) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == data:
            return path
        if not force:
            raise ProductMissionError("INTAKE_ARTIFACT_EXISTS", f"refusing to replace {path}; use --force")
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def _text(value: str, field: str, *, minimum: int = 8, maximum: int = MAX_TEXT) -> str:
    cleaned = value.strip()
    if not minimum <= len(cleaned) <= maximum or "\x00" in cleaned or _SECRET.search(cleaned):
        raise ProductMissionError("INTAKE_DECISION_INVALID", f"{field} must contain {minimum}-{maximum} non-secret characters")
    return cleaned


def _clear_decision(value: str, field: str, *, observable: bool = False) -> str:
    """Reject unresolved or non-observable AI-authored decision text."""
    try:
        return require_clear(value, field=field, require_action=True, require_observable=observable)
    except IntentQualityError as exc:
        raise ProductMissionError("INTAKE_INTENT_UNCLEAR", f"{field}: {exc.message}") from exc


def _frameworks(text: str) -> list[dict[str, Any]]:
    lowered = text.lower()
    matches: list[dict[str, Any]] = []
    for item in _FRAMEWORKS:
        signals = [signal for signal in item["signals"] if signal in lowered]
        if signals:
            matches.append({"id": item["id"], "label": item["label"], "matched_terms": signals, "use_when": item["use_when"]})
    if not matches:
        fallback = next(item for item in _FRAMEWORKS if item["id"] == "custom")
        matches.append({"id": fallback["id"], "label": fallback["label"], "matched_terms": [], "use_when": fallback["use_when"]})
    return matches


def _question_tree(shortlist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": "Q-FRAMEWORK", "order": 10, "status": "decision_required",
            "prompt": "Which framework or delivery surface will this first mission use?",
            "choices": [item["id"] for item in shortlist], "depends_on": [],
            "evidence": "The shortlist is a deterministic match against declared PRD terms; it is not a framework recommendation.",
        },
        {
            "id": "Q-INTENT", "order": 20, "status": "decision_required",
            "prompt": "State the exact user or operator outcome this mission must create, without naming an implementation.",
            "depends_on": ["Q-FRAMEWORK"],
        },
        {
            "id": "Q-ACCEPTANCE", "order": 30, "status": "decision_required",
            "prompt": "State the exact observable evidence that would show the intent was met, including the boundary where it will be checked.",
            "depends_on": ["Q-INTENT"],
        },
        {
            "id": "Q-FORBIDDEN", "order": 40, "status": "decision_required",
            "prompt": "What must never happen, even if the primary outcome appears to succeed?",
            "depends_on": ["Q-INTENT"],
            "evidence": "Record a user, safety, data, authority, or scope boundary. It becomes a forbidden behavior in the sealed Oracle Contract, not an agent-supplied test tolerance.",
        },
        {
            "id": "Q-NEGATIVE-CASE", "order": 50, "status": "decision_required",
            "prompt": "Which counterexample must fail or be refused to prove the boundary is real?",
            "depends_on": ["Q-FORBIDDEN", "Q-ACCEPTANCE"],
            "evidence": "Name one observable negative case. The independent challenge lane mutates the implementation against this contract; it does not let the worker rewrite the oracle.",
        },
        {
            "id": "Q-EXTERNAL-EFFECTS", "order": 60, "status": "decision_required",
            "prompt": "Will the mission remain local-only, or does any publish, deploy, message, credential, connector, payment, or irreversible effect require a human-controlled boundary?",
            "choices": sorted(_EXTERNAL_EFFECTS), "depends_on": ["Q-INTENT"],
        },
        {
            "id": "Q-PR-REVIEW", "order": 70, "status": "decision_required",
            "prompt": "What exact diff, reviewer, and independent evidence must be present before this change can be reviewed?",
            "depends_on": ["Q-ACCEPTANCE", "Q-NEGATIVE-CASE"],
            "evidence": "The PR stage compares the sealed contract to the observed diff and receipt set. A green worker-authored test suite alone is insufficient.",
        },
        {
            "id": "Q-RE-EVALUATE", "order": 80, "status": "optional",
            "prompt": "What fact would require this framework or intent decision to be revisited?",
            "depends_on": ["Q-FRAMEWORK", "Q-INTENT"],
        },
    ]


def _markdown(receipt: dict[str, Any]) -> str:
    lines = [
        f"# Intake Grill: {receipt['project']}", "",
        f"Source SHA-256: `{receipt['source']['sha256']}`", "",
        "This is a decision worksheet. It does not choose a framework, infer the product intent, create a mission, or authorize implementation or external effects.", "",
        "## Decision sequence", "",
    ]
    for question in receipt["questions"]:
        lines.extend([
            f"### {question['id']}", "", question["prompt"], "",
            f"**Depends on:** {', '.join(question['depends_on']) if question['depends_on'] else 'nothing'}", "",
        ])
        if question.get("choices"):
            lines.extend([f"**Choices:** {', '.join(question['choices'])}", ""])
        if question.get("evidence"):
            lines.extend([f"**Boundary:** {question['evidence']}", ""])
        lines.extend(["**Answer:**", ">", ""])
    lines.extend([
        "## Next step", "",
        "A named human records the selected framework, exact intent, observable acceptance evidence, and external-effects posture with `factory intake confirm`. Before code, seal the intent as an Oracle Contract with the forbidden behavior, negative case, source hashes, and approved gate values. Before merge, use Proof Review to bind the observed diff and independent evidence back to that contract. Bind the intake confirmation during `factory product compile --intake ...` before creating a mission.", "",
    ])
    return "\n".join(lines)


def _core(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in receipt.items() if key not in {"intake_sha256", "generated_at"}}


def _load_receipt(root: Path, value: Path | str, field: str, schema: str) -> tuple[Path, str, dict[str, Any]]:
    path, relative = _relative(root, value, field)
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductMissionError("INTAKE_RECEIPT_INVALID", f"{field} must be readable JSON") from exc
    if not isinstance(receipt, dict) or receipt.get("schema") != schema:
        raise ProductMissionError("INTAKE_RECEIPT_INVALID", f"{field} must use {schema}")
    return path, relative, receipt


def _sealed_receipt(path: Path, schema: str, core: dict[str, Any], hash_field: str,
                    timestamp_field: str, *, force: bool) -> tuple[dict[str, Any], bool]:
    digest = _sha(core)
    if path.is_file() and not force:
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProductMissionError("INTAKE_ARTIFACT_INVALID", f"cannot read existing receipt: {path}") from exc
        if isinstance(existing, dict) and existing.get("schema") == schema and existing.get(hash_field) == digest:
            return existing, True
        raise ProductMissionError("INTAKE_ARTIFACT_EXISTS", f"refusing to replace {path}; use --force")
    return {**core, hash_field: digest, timestamp_field: _now()}, False


def grill_intake(prd_path: Path, root: Path, project: str | None = None, out_path: Path | None = None,
                 force: bool = False) -> dict[str, Any]:
    """Write a source-bound framework and intent decision worksheet."""
    workspace = Path(root).resolve()
    path, relative, source = _read_prd(workspace, prd_path)
    analysis = analyze_product_text(source.decode("utf-8"), source_name=path.name, project=project)
    project_id = _project_id(analysis["project"])
    source_sha = _sha_bytes(source)
    shortlist = _frameworks(source.decode("utf-8"))
    core = {
        "schema": INTAKE_GRILL_SCHEMA,
        "project": project_id,
        "status": "needs_confirmation",
        "source": {"path": relative, "name": path.name, "sha256": source_sha, "bytes": len(source)},
        "framework_shortlist": shortlist,
        "questions": _question_tree(shortlist),
        "observed_product_gaps": analysis["gaps"],
        "markers": ["INTAKE_SOURCE_BOUND", "INTAKE_DECISION_TREE", "INTAKE_HUMAN_CONFIRMATION_REQUIRED", "INTAKE_ZERO_EXECUTION_AUTHORITY"],
        "authority": _AUTHORITY,
    }
    directory = workspace / ".factory" / "intake-grills" / project_id
    receipt_path = directory / f"{source_sha}.json"
    source_path = directory / f"{source_sha}.source.md"
    raw_out = Path(out_path) if out_path else None
    markdown_path = raw_out.resolve() if raw_out and raw_out.is_absolute() else (workspace / raw_out if raw_out else directory / f"{source_sha}.md")
    if out_path:
        _relative(workspace, markdown_path, "out", exists=False)
    result, reused = _sealed_receipt(receipt_path, INTAKE_GRILL_SCHEMA, core, "intake_sha256", "generated_at", force=force)
    _atomic_write(source_path, source, force=force)
    _atomic_write(receipt_path, json.dumps(result, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n", force=force)
    _atomic_write(markdown_path, _markdown(result).encode("utf-8"), force=force)
    return {**result, "path": str(receipt_path), "markdown": str(markdown_path), "source_copy": str(source_path), "idempotent": reused}


def verify_intake_grill(root: Path, receipt_path: Path) -> dict[str, Any]:
    """Verify an Intake Grill receipt and its captured PRD bytes."""
    workspace = Path(root).resolve()
    path, relative, receipt = _load_receipt(workspace, receipt_path, "intake", INTAKE_GRILL_SCHEMA)
    errors: list[str] = []
    if receipt.get("intake_sha256") != _sha(_core(receipt)):
        errors.append("receipt hash mismatch")
    source = receipt.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("sha256"), str) or not _SHA.fullmatch(source["sha256"]):
        errors.append("source binding invalid")
    else:
        captured = path.with_name(f"{source['sha256']}.source.md")
        if not captured.is_file():
            errors.append("captured source missing")
        elif _sha_bytes(captured.read_bytes()) != source["sha256"]:
            errors.append("captured source drift")
    if receipt.get("authority") != _AUTHORITY:
        errors.append("authority boundary invalid")
    return {"schema": "factory.intake-grill.verification.v1", "valid": not errors, "marker": "INTAKE_VERIFIED" if not errors else "INTAKE_DRIFT", "path": relative, "errors": errors}


def _confirmation_core(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in receipt.items() if key not in {"confirmation_sha256", "confirmed_at"}}


def confirm_intake(root: Path, intake_path: Path, framework: str, intent: str, acceptance: str,
                   external_effects: str, approved_by: str, rationale: str, re_evaluate_when: str | None = None,
                   out_path: Path | None = None, force: bool = False) -> dict[str, Any]:
    """Bind named human intake decisions without initiating delivery work."""
    workspace = Path(root).resolve()
    intake_verification = verify_intake_grill(workspace, intake_path)
    if not intake_verification["valid"]:
        raise ProductMissionError("INTAKE_SOURCE_DRIFT", "; ".join(intake_verification["errors"]))
    intake_file, intake_relative, intake = _load_receipt(workspace, intake_path, "intake", INTAKE_GRILL_SCHEMA)
    allowed = {item["id"] for item in intake.get("framework_shortlist", []) if isinstance(item, dict) and isinstance(item.get("id"), str)}
    if framework not in allowed:
        raise ProductMissionError("INTAKE_FRAMEWORK_NOT_SHORTLISTED", "framework must be one of the source-bound shortlist choices")
    if external_effects not in _EXTERNAL_EFFECTS:
        raise ProductMissionError("INTAKE_EXTERNAL_EFFECTS_INVALID", "external_effects must be local_only or human_controlled")
    approver = _text(approved_by, "approved_by", minimum=2, maximum=120)
    intent_value = _text(intent, "intent")
    acceptance_value = _text(acceptance, "acceptance")
    _clear_decision(intent_value, "intent")
    _clear_decision(acceptance_value, "acceptance", observable=True)
    decision = {
        "framework": framework,
        "intent": intent_value,
        "acceptance": acceptance_value,
        "external_effects": external_effects,
        "approved_by": approver,
        "rationale": _text(rationale, "rationale"),
        "re_evaluate_when": _text(re_evaluate_when, "re_evaluate_when") if re_evaluate_when else None,
    }
    source = intake["source"]
    core = {
        "schema": INTAKE_CONFIRMATION_SCHEMA,
        "project": intake["project"],
        "status": "confirmed",
        "intake": {"path": intake_relative, "intake_sha256": intake["intake_sha256"]},
        "source": {"sha256": source["sha256"], "bytes": source["bytes"]},
        "decision": decision,
        "markers": ["INTAKE_CONFIRMATION_SOURCE_BOUND", "INTAKE_NAMED_HUMAN_BOUND", "INTAKE_INTENT_CLARITY_CHECKED", "INTAKE_ACCEPTANCE_OBSERVABLE_CHECKED", "INTAKE_REEVALUATION_EXPLICIT", "INTAKE_ZERO_EXECUTION_AUTHORITY"],
        "authority": _AUTHORITY,
    }
    default = workspace / ".factory" / "intake-confirmations" / intake["project"] / f"{source['sha256']}.json"
    raw_out = Path(out_path) if out_path else None
    path = raw_out.resolve() if raw_out and raw_out.is_absolute() else (workspace / raw_out if raw_out else default)
    _relative(workspace, path, "out", exists=False)
    confirmation, reused = _sealed_receipt(path, INTAKE_CONFIRMATION_SCHEMA, core, "confirmation_sha256", "confirmed_at", force=force)
    _atomic_write(path, json.dumps(confirmation, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n", force=force)
    return {**confirmation, "path": str(path), "idempotent": reused}


def _confirmation_base_errors(confirmation: dict[str, Any]) -> tuple[list[str], dict[str, Any] | None]:
    errors: list[str] = []
    if confirmation.get("confirmation_sha256") != _sha(_confirmation_core(confirmation)):
        errors.append("confirmation hash mismatch")
    if confirmation.get("authority") != _AUTHORITY or confirmation.get("status") != "confirmed":
        errors.append("confirmation boundary invalid")
    decision = confirmation.get("decision")
    if not isinstance(decision, dict) or set(decision) != {"framework", "intent", "acceptance", "external_effects", "approved_by", "rationale", "re_evaluate_when"}:
        errors.append("decision fields invalid")
    elif decision.get("external_effects") not in _EXTERNAL_EFFECTS:
        errors.append("external effects invalid")
    if decision is not None:
        try:
            _clear_decision(decision.get("intent"), "intent")
            _clear_decision(decision.get("acceptance"), "acceptance", observable=True)
        except (ProductMissionError, TypeError) as exc:
            errors.append(str(exc))
    return errors, decision if isinstance(decision, dict) else None


def _confirmation_binding_errors(workspace: Path, confirmation: dict[str, Any], decision: dict[str, Any] | None) -> list[str]:
    errors: list[str] = []
    intake = confirmation.get("intake")
    if not isinstance(intake, dict) or set(intake) != {"path", "intake_sha256"}:
        errors.append("intake binding invalid")
        return errors
    try:
        intake_path, _, intake_receipt = _load_receipt(workspace, intake["path"], "intake", INTAKE_GRILL_SCHEMA)
        verified = verify_intake_grill(workspace, intake_path)
    except ProductMissionError as exc:
        return [exc.code]
    if not verified["valid"]:
        return list(verified["errors"])
    if intake_receipt.get("intake_sha256") != intake.get("intake_sha256"):
        return ["intake hash mismatch"]
    choices = {item.get("id") for item in intake_receipt.get("framework_shortlist", []) if isinstance(item, dict)}
    if decision is not None and decision.get("framework") not in choices:
        errors.append("framework not in source-bound shortlist")
    source = confirmation.get("source")
    if not isinstance(source, dict) or source.get("sha256") != intake_receipt.get("source", {}).get("sha256"):
        errors.append("source hash mismatch")
    return errors


def verify_intake_confirmation(root: Path, receipt_path: Path) -> dict[str, Any]:
    """Verify confirmed intake against the source-bound worksheet and PRD copy."""
    workspace = Path(root).resolve()
    _, relative, confirmation = _load_receipt(workspace, receipt_path, "confirmation", INTAKE_CONFIRMATION_SCHEMA)
    errors, decision = _confirmation_base_errors(confirmation)
    errors.extend(_confirmation_binding_errors(workspace, confirmation, decision))
    return {
        "schema": "factory.intake-confirmation.verification.v1", "valid": not errors,
        "marker": "INTAKE_CONFIRMATION_VERIFIED" if not errors else "INTAKE_CONFIRMATION_DRIFT",
        "path": relative, "errors": errors,
        "confirmation": confirmation if not errors else None,
    }


def intake_status(root: Path, prd_path: Path | None = None) -> dict[str, Any]:
    """Read local intake and confirmation facts; never starts or approves work."""
    workspace = Path(root).resolve()
    source_sha: str | None = None
    if prd_path is not None:
        _, _, source = _read_prd(workspace, prd_path)
        source_sha = _sha_bytes(source)
    rows: list[dict[str, Any]] = []
    for path in sorted((workspace / ".factory" / "intake-confirmations").glob("*/*.json")):
        check = verify_intake_confirmation(workspace, path)
        confirmation = check.get("confirmation")
        if source_sha is not None and (not confirmation or confirmation.get("source", {}).get("sha256") != source_sha):
            continue
        rows.append({"path": check["path"], "valid": check["valid"], "marker": check["marker"], "project": confirmation.get("project") if confirmation else None, "framework": confirmation.get("decision", {}).get("framework") if confirmation else None})
    latest = rows[-1] if rows else None
    return {
        "schema": "factory.intake.status.v1", "found": bool(latest),
        "marker": latest["marker"] if latest else "INTAKE_CONFIRMATION_REQUIRED",
        "latest": latest, "confirmation_count": len(rows), "source_sha256": source_sha,
        "authority": _AUTHORITY,
        "scope": "Read-only intake status; it never infers a decision, creates a mission, or authorizes implementation.",
    }
