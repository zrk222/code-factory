"""A deterministic, one-question-at-a-time intent grill for CF/ForgeLine.

This borrows the useful mechanics of Matt Pocock's grill workflow without
copying prompts or allowing an agent to answer decisions: facts may be
resolved from the supplied source, decisions require a named human answer,
and the final contract has an explicit confirmation stop-gate.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any


SCHEMA = "factory.grill-session.v1"
_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,79}$")


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _session_path(root: Path, session_id: str) -> Path:
    if not isinstance(session_id, str) or not _ID.fullmatch(session_id):
        raise ValueError("session_id must use lowercase letters, digits, hyphens, or underscores")
    return Path(root).resolve() / ".factory" / "grill-sessions" / f"{session_id}.json"


def _questions() -> list[dict[str, Any]]:
    return [
        {"id": "intent", "kind": "decision", "prompt": "What exact user or operator outcome must this change create?", "required": True},
        {"id": "actors", "kind": "fact", "prompt": "Who is the primary actor and who owns the consequential decision?", "required": True},
        {"id": "scope", "kind": "decision", "prompt": "What is explicitly in scope, and what is out of scope for this slice?", "required": True},
        {"id": "acceptance", "kind": "decision", "prompt": "What observable evidence proves the outcome, and where will it be checked?", "required": True},
        {"id": "forbidden", "kind": "decision", "prompt": "What must never happen even if the happy path succeeds?", "required": True},
        {"id": "negative_case", "kind": "decision", "prompt": "Which counterexample must fail or be refused to prove the boundary?", "required": True},
        {"id": "reconsideration", "kind": "decision", "prompt": "What fact would force this decision to be revisited?", "required": False},
    ]


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read(root: Path, session_id: str) -> dict[str, Any]:
    path = _session_path(root, session_id)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ValueError("invalid grill session")
    return value


def start_grill(root: Path, session_id: str, source: Path | None = None) -> dict[str, Any]:
    """Create or idempotently reopen a source-bound, human-owned grill session."""
    workspace = Path(root).resolve()
    if source is not None:
        source_path = source if source.is_absolute() else workspace / source
        source_path = source_path.resolve()
        source_path.relative_to(workspace)
        raw = source_path.read_bytes()
        if len(raw) > 65_536:
            raise ValueError("source exceeds 65536 bytes")
        source_meta = {"path": source_path.relative_to(workspace).as_posix(), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    else:
        source_meta = None
    questions = _questions()
    core = {"schema": SCHEMA, "session_id": session_id, "status": "questioning", "source": source_meta, "questions": questions, "answers": {}, "facts": [], "decisions": [], "confirmed_by": None}
    path = _session_path(workspace, session_id)
    if path.exists():
        existing = _read(workspace, session_id)
        if existing.get("session_sha256") == _sha(core):
            return {**existing, "path": path.relative_to(workspace).as_posix(), "idempotent": True}
        raise ValueError("session already exists with different source; choose a new session_id")
    session = {**core, "session_sha256": _sha(core), "created_at": _now(), "updated_at": _now(), "authority": {"execute": False, "approve": False, "publish": False}}
    _write(path, session)
    return {**session, "path": path.relative_to(workspace).as_posix(), "next": questions[0], "idempotent": False}


def next_question(root: Path, session_id: str) -> dict[str, Any]:
    """Return the next required question or the explicit confirmation frontier."""
    session = _read(root, session_id)
    answers = session.get("answers", {})
    for question in session.get("questions", []):
        # Optional prompts are useful during a live grill but never hold the
        # deterministic confirmation gate open. Required intent, scope,
        # acceptance, forbidden, and negative-case answers are the contract.
        if question["id"] not in answers and question.get("required", False):
            return {"schema": "factory.grill-next.v1", "session_id": session_id, "status": "QUESTION_REQUIRED", "question": question, "answered": len(answers), "total": len(session["questions"]), "claim_boundary": "One question only; no implementation or approval authority."}
    if session.get("status") != "confirmed":
        return {"schema": "factory.grill-next.v1", "session_id": session_id, "status": "CONFIRMATION_REQUIRED", "question": None, "answered": len(answers), "total": len(session["questions"]), "claim_boundary": "Shared understanding is complete but still requires named human confirmation."}
    return {"schema": "factory.grill-next.v1", "session_id": session_id, "status": "COMPLETE", "question": None, "answered": len(answers), "total": len(session["questions"]), "claim_boundary": "Confirmed intent worksheet only; no execution or release authority."}


def answer_question(root: Path, session_id: str, question_id: str, answer: str, *, answered_by: str) -> dict[str, Any]:
    """Record one immutable human answer and return the next bounded frontier."""
    session = _read(root, session_id)
    if not isinstance(answer, str) or not 2 <= len(answer.strip()) <= 2_000:
        raise ValueError("answer must contain 2-2000 characters")
    if not isinstance(answered_by, str) or not answered_by.strip():
        raise ValueError("answered_by is required")
    question = next((item for item in session["questions"] if item["id"] == question_id), None)
    if question is None:
        raise ValueError("unknown question_id")
    if question_id in session["answers"]:
        raise ValueError("question already answered; use a new session to change it")
    session["answers"][question_id] = {"answer": answer.strip(), "answered_by": answered_by.strip(), "answered_at": _now(), "kind": question["kind"]}
    bucket = "facts" if question["kind"] == "fact" else "decisions"
    session[bucket].append({"id": question_id, "answer": answer.strip()})
    session["updated_at"] = _now()
    _write(_session_path(root, session_id), session)
    return {**session, "next": next_question(root, session_id)}


def confirm_grill(root: Path, session_id: str, *, approved_by: str) -> dict[str, Any]:
    """Seal a fully answered grill with a named human confirmation digest."""
    session = _read(root, session_id)
    missing = [item["id"] for item in session["questions"] if item.get("required") and item["id"] not in session["answers"]]
    if missing:
        raise ValueError(f"required questions unanswered: {', '.join(missing)}")
    if not isinstance(approved_by, str) or not approved_by.strip():
        raise ValueError("approved_by is required")
    session["status"] = "confirmed"
    session["confirmed_by"] = approved_by.strip()
    session["confirmed_at"] = _now()
    session["updated_at"] = session["confirmed_at"]
    session["confirmation_sha256"] = _sha({key: value for key, value in session.items() if key not in {"confirmation_sha256", "updated_at"}})
    _write(_session_path(root, session_id), session)
    return {**session, "next": next_question(root, session_id)}
