"""Bounded, local PRD clarification artifacts before product compilation."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from .product_missions import ProductMissionError, analyze_product_text


PRD_GRILL_SCHEMA = "factory.prd_grill.v1"
MAX_QUESTIONS = {"quick": 3, "deep": 5}
_QUICK_CODES = {
    "REQUIREMENTS_MISSING", "ACCEPTANCE_MISSING", "ACTORS_MISSING",
    "OUTCOMES_MISSING", "JOURNEYS_MISSING", "TRUST_BOUNDARIES_MISSING",
    "APPROVAL_REQUIREMENTS_MISSING", "SUCCESS_EVENTS_MISSING",
}
_QUESTION_SPECS = {
    "REQUIREMENTS_MISSING": {
        "id": "Q-REQUIREMENTS", "order": 10, "section": "Requirements",
        "title": "What must the first release demonstrably do?",
        "prompt": "List the smallest set of observable system or user behaviours needed for the first release.",
        "recommendation": "Write one to three EARS requirements, each with one observable outcome and no implementation guess.",
        "depends_on": [],
    },
    "ACTORS_MISSING": {
        "id": "Q-ACTORS", "order": 20, "section": "Actors",
        "title": "Who owns each important action?",
        "prompt": "Name the user, operator, reviewer, or system role that starts, approves, and consumes the workflow.",
        "recommendation": "Start with the primary user and the human owner for irreversible actions.",
        "depends_on": [],
    },
    "OUTCOMES_MISSING": {
        "id": "Q-OUTCOMES", "order": 30, "section": "Outcomes",
        "title": "What measurable change makes this worth shipping?",
        "prompt": "State one outcome, its unit, and the threshold or event that would show progress.",
        "recommendation": "Choose one observable event or bounded time, quality, or completion measure; keep unavailable baselines explicit.",
        "depends_on": [],
    },
    "JOURNEYS_MISSING": {
        "id": "Q-JOURNEY", "order": 40, "section": "Journeys and business rules",
        "title": "What is the first end-to-end journey?",
        "prompt": "Describe the smallest user journey from trigger to visible success, including the decision point that matters.",
        "recommendation": "Use one primary actor and one success state before adding alternative flows.",
        "depends_on": ["Q-ACTORS"],
    },
    "ACCEPTANCE_MISSING": {
        "id": "Q-ACCEPTANCE", "order": 50, "section": "Acceptance",
        "title": "How will the team know the requirement works?",
        "prompt": "Provide a Given/When/Then scenario for the most important requirement.",
        "recommendation": "Cover the primary journey first, with an externally observable Then clause.",
        "depends_on": ["Q-REQUIREMENTS"],
    },
    "DATA_OWNERSHIP_MISSING": {
        "id": "Q-DATA-OWNERSHIP", "order": 60, "section": "Data ownership and trust boundaries",
        "title": "Who controls the product data?",
        "prompt": "State who owns data and how retention, export, and deletion are controlled.",
        "recommendation": "Name the accountable owner and the user-controlled export or deletion boundary.",
        "depends_on": [],
    },
    "TRUST_BOUNDARIES_MISSING": {
        "id": "Q-TRUST", "order": 70, "section": "Data ownership and trust boundaries",
        "title": "What data or authority boundary must stay intact?",
        "prompt": "Name the boundary that prevents unsafe disclosure, authority escalation, or cross-tenant access.",
        "recommendation": "Prefer an explicit workspace, tenant, credential, or approval boundary over a generic security claim.",
        "depends_on": [],
    },
    "APPROVAL_REQUIREMENTS_MISSING": {
        "id": "Q-APPROVAL", "order": 80, "section": "External effects and approvals",
        "title": "Which effects require a human decision?",
        "prompt": "List any publish, deploy, delete, payment, credential, connector, or external-message action that needs approval.",
        "recommendation": "Keep irreversible or externally visible effects human-controlled by default.",
        "depends_on": [],
    },
    "SUCCESS_EVENTS_MISSING": {
        "id": "Q-SUCCESS-EVENT", "order": 90, "section": "Success events",
        "title": "Which event proves the intended outcome?",
        "prompt": "Name the event and measurement boundary that will show the product outcome happened.",
        "recommendation": "Record an observed or measured event; do not infer causal improvement without a baseline.",
        "depends_on": ["Q-OUTCOMES"],
    },
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: bytes) -> str:
    return sha256(value).hexdigest()


def _atomic_write(path: Path, data: bytes, *, force: bool) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == data:
            return path
        if not force:
            raise ProductMissionError("ARTIFACT_EXISTS", f"refusing to replace {path}; use --force")
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


def _read_prd(path: Path) -> bytes:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise ProductMissionError("PRD_NOT_FOUND", f"cannot read PRD: {path}") from exc
    if not data or len(data) > 65536:
        raise ProductMissionError("PRD_SIZE_INVALID", "PRD must be 1-65536 UTF-8 bytes")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProductMissionError("PRD_ENCODING_INVALID", "PRD must be valid UTF-8") from exc
    return data


def _repository_facts(root: Path) -> list[dict[str, str]]:
    workspace = Path(root).resolve()
    facts: list[dict[str, str]] = []
    for name in ("pyproject.toml", "package.json", "README.md", "Cargo.toml", "go.mod"):
        candidate = workspace / name
        if candidate.is_file():
            facts.append({"kind": "allowlisted_workspace_file", "path": name, "sha256": _sha(candidate.read_bytes())})
    return facts


def _question(code: str, gap: dict[str, str]) -> dict[str, Any]:
    if code.startswith("UX_") and code.endswith("_MISSING"):
        state = code.removeprefix("UX_").removesuffix("_MISSING").lower()
        return {
            "id": f"Q-UX-{state.upper()}", "order": 100, "section": "Experience states",
            "title": f"What should the {state} state communicate?",
            "prompt": f"Describe the user-safe {state} state for the primary journey.",
            "recommendation": "State what remains visible, the next safe action, and any permission or recovery boundary.",
            "depends_on": ["Q-REQUIREMENTS"],
            "gap_code": code, "severity": gap["severity"], "evidence": gap["message"],
        }
    spec = _QUESTION_SPECS.get(code)
    if not spec:
        raise ProductMissionError("PRD_GRILL_GAP_UNSUPPORTED", f"no deterministic question for observed gap {code}")
    return {**spec, "gap_code": code, "severity": gap["severity"], "evidence": gap["message"]}


def _frontier(gaps: list[dict[str, str]], mode: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidates = [_question(item["code"], item) for item in gaps if mode == "deep" or item["code"] in _QUICK_CODES]
    missing_ids = {item["id"] for item in candidates}
    ready = [item for item in candidates if not (set(item["depends_on"]) & missing_ids)]
    deferred = [
        {**item, "status": "deferred", "deferred_by": sorted(set(item["depends_on"]) & missing_ids)}
        for item in candidates if set(item["depends_on"]) & missing_ids
    ]
    ready.sort(key=lambda item: (item["order"], item["id"]))
    selected, overflow = ready[:MAX_QUESTIONS[mode]], ready[MAX_QUESTIONS[mode]:]
    deferred.extend({**item, "status": "deferred", "deferred_by": ["round_limit"]} for item in overflow)
    selected = [{**item, "status": "question"} for item in selected]
    deferred.sort(key=lambda item: (item["order"], item["id"]))
    return selected, deferred


def _markdown(receipt: dict[str, Any]) -> str:
    lines = [
        f"# PRD Grill: {receipt['project']}", "",
        f"Source SHA-256: `{receipt['source']['sha256']}`", "",
        "This is a clarification sheet. It does not modify the source PRD, approve implementation, or authorize external effects.", "",
    ]
    if receipt["questions"]:
        lines.extend(["## Current question frontier", ""])
        for item in receipt["questions"]:
            lines.extend([
                f"### {item['id']} — {item['title']}", "", item["prompt"], "",
                f"**Recommended starting point:** {item['recommendation']}", "",
                f"**Target PRD section:** {item['section']}", "",
                f"**Observed evidence:** {item['evidence']}", "", "**Answer:**", ">", "",
            ])
    if receipt["deferred_questions"]:
        lines.extend(["## Deferred decisions", ""])
        for item in receipt["deferred_questions"]:
            lines.append(f"- `{item['id']}` waits for: {', '.join(item['deferred_by'])}.")
        lines.append("")
    if not receipt["questions"] and not receipt["deferred_questions"]:
        lines.extend(["## Shared-understanding check", "", "No observed PRD gaps require a clarification question. A human still confirms the product contract before implementation.", ""])
    lines.extend(["## Next step", "", "Update the PRD deliberately, then rerun PRD Grill and `specline optimize-prd`. Do not treat this sheet or its recommendations as implementation approval.", ""])
    return "\n".join(lines)


def _receipt_for_core(receipt_path: Path, core: dict[str, Any], *, force: bool) -> tuple[dict[str, Any], bool]:
    core_sha = _sha(_canonical(core))
    if not receipt_path.is_file() or force:
        return {**core, "grill_sha256": core_sha, "generated_at": _now()}, False
    try:
        existing = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductMissionError("ARTIFACT_INVALID", f"cannot read PRD Grill receipt: {receipt_path}") from exc
    if existing.get("grill_sha256") == core_sha:
        return existing, True
    raise ProductMissionError("ARTIFACT_EXISTS", f"refusing to replace {receipt_path}; use --force")


def _write_grill_artifacts(source_path: Path, receipt_path: Path, markdown_path: Path,
                           source: bytes, receipt: dict[str, Any], *, force: bool) -> None:
    encoded = json.dumps(receipt, sort_keys=True).encode("utf-8") + b"\n"
    _atomic_write(source_path, source, force=force)
    _atomic_write(receipt_path, encoded, force=force)
    _atomic_write(markdown_path, _markdown(receipt).encode("utf-8"), force=force)


def grill_prd(prd_path: Path, root: Path, mode: str = "quick", project: str | None = None,
              out_path: Path | None = None, confirm: bool = False, force: bool = False) -> dict[str, Any]:
    """Write a bounded, source-bound PRD clarification receipt and question sheet."""
    if mode not in MAX_QUESTIONS:
        raise ProductMissionError("PRD_GRILL_MODE_INVALID", "mode must be quick or deep")
    source = _read_prd(Path(prd_path))
    analysis = analyze_product_text(source.decode("utf-8"), source_name=Path(prd_path).name, project=project)
    questions, deferred = _frontier(analysis["gaps"], mode)
    if confirm and analysis["gaps"]:
        raise ProductMissionError("PRD_GRILL_UNRESOLVED", "cannot confirm shared understanding while clarification questions remain")
    project_id, source_sha = analysis["project"], _sha(source)
    status = "confirmed" if confirm else ("needs_input" if analysis["gaps"] else "ready_for_confirmation")
    core = {
        "schema": PRD_GRILL_SCHEMA, "project": project_id, "mode": mode, "status": status,
        "source": {"name": Path(prd_path).name, "sha256": source_sha, "bytes": len(source)},
        "repository_facts": _repository_facts(Path(root)), "observed_gaps": analysis["gaps"],
        "questions": questions, "deferred_questions": deferred,
        "markers": [
            "PRD_GRILL_SOURCE_BOUND", "PRD_GRILL_FACTS_LOCAL", "PRD_GRILL_QUESTIONS_BOUND",
            "PRD_GRILL_DRAFT_REVIEW_REQUIRED", *(["PRD_GRILL_SHARED_UNDERSTANDING_CONFIRMED"] if confirm else []),
        ],
        "authority": {"implementation": "not_authorized", "external_effects": "not_authorized"},
    }
    directory = Path(root).resolve() / ".factory" / "prd-grills" / project_id
    receipt_path = directory / f"{source_sha}.json"
    source_path = directory / f"{source_sha}.source.md"
    markdown_path = Path(out_path) if out_path else directory / f"{source_sha}.md"
    receipt, reused = _receipt_for_core(receipt_path, core, force=force)
    _write_grill_artifacts(source_path, receipt_path, markdown_path, source, receipt, force=force)
    return {**receipt, "path": str(receipt_path), "markdown": str(markdown_path), "source_copy": str(source_path), "idempotent": reused}


def verify_prd_grill(receipt_path: Path) -> dict[str, Any]:
    """Verify a PRD Grill receipt and its captured source binding."""
    try:
        receipt = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductMissionError("ARTIFACT_INVALID", f"cannot read PRD Grill receipt: {receipt_path}") from exc
    if not isinstance(receipt, dict) or receipt.get("schema") != PRD_GRILL_SCHEMA:
        raise ProductMissionError("SCHEMA_UNSUPPORTED", f"expected {PRD_GRILL_SCHEMA}: {receipt_path}")
    core = {key: value for key, value in receipt.items() if key not in {"grill_sha256", "generated_at"}}
    errors: list[str] = []
    if receipt.get("grill_sha256") != _sha(_canonical(core)):
        errors.append("receipt hash mismatch")
    source_path = Path(receipt_path).with_name(f"{receipt['source']['sha256']}.source.md")
    if not source_path.is_file():
        errors.append("captured source is missing")
    elif _sha(source_path.read_bytes()) != receipt["source"]["sha256"]:
        errors.append("captured source hash mismatch")
    return {"valid": not errors, "marker": "PRD_GRILL_VERIFIED" if not errors else "PRD_GRILL_DRIFT", "errors": errors, "receipt": str(receipt_path)}
