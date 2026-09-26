"""Deterministic contracts for the AI-native SDLC blueprint.

This module composes local evidence only.  It provides bounded retain/recall/
reflect memory facts, a Bronze/Silver/Gold librarian promotion contract,
production-signal-to-intent proposals, access profiles, and typed team plans.
It never calls a model, contacts a provider, creates a container, executes a
task, or grants release authority.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Iterable


BLUEPRINT_SCHEMA = "factory.ai-native-blueprint.v1"
MEMORY_SCHEMA = "factory.blueprint-memory.v1"
LIBRARIAN_SCHEMA = "factory.blueprint-librarian.v1"
INTENT_SCHEMA = "factory.blueprint-intent-proposal.v1"
ACCESS_SCHEMA = "factory.blueprint-access-profile.v1"
TEAM_SCHEMA = "factory.blueprint-team-plan.v1"
ARTIFACT_SCHEMA = "factory.blueprint-artifact-chain.v1"
MAX_OBSERVATIONS = 500
MAX_TASKS = 100
MODEL_TIERS = {"lightweight", "workhorse", "frontier"}
MEMORY_CLASSES = {"fact", "unknown", "uncertain"}
LIBRARIAN_STAGES = {"bronze", "silver", "gold", "contested"}
ACCESS_PROFILES = {"read_write", "read_only", "masked"}
ARTIFACT_STATUSES = {"draft", "approved", "processed"}


class BlueprintError(ValueError):
    """Closed-class blueprint contract failure."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _text(value: object, field: str, maximum: int = 240) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.strip()) > maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise BlueprintError(
            "E_BLUEPRINT_SCHEMA", f"{field} must be bounded printable text"
        )
    return value.strip()


def _digest(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise BlueprintError(
            "E_BLUEPRINT_DIGEST", f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _document(value: object, field: str, maximum: int = 20000) -> str:
    """Validate bounded UTF-8 document text while allowing Markdown newlines."""
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise BlueprintError(
            "E_BLUEPRINT_SCHEMA", f"{field} must be bounded document text"
        )
    if any(ord(char) < 9 or (13 < ord(char) < 32) for char in value):
        raise BlueprintError(
            "E_BLUEPRINT_SCHEMA", f"{field} contains unsupported control characters"
        )
    return value.strip()


def _timestamp(value: object, field: str = "observed_at") -> str:
    text = _text(value, field, 64).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise BlueprintError("E_BLUEPRINT_TIME", f"{field} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise BlueprintError("E_BLUEPRINT_TIME", f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _list(values: Iterable[object], field: str, maximum: int = 40) -> list[str]:
    if isinstance(values, (str, bytes)):
        raise BlueprintError("E_BLUEPRINT_SCHEMA", f"{field} must be a list")
    result = sorted({_text(item, field, 120) for item in values})
    if len(result) > maximum:
        raise BlueprintError(
            "E_BLUEPRINT_LIMIT", f"{field} may contain at most {maximum} items"
        )
    return result


def _seal(core: dict[str, Any], field: str) -> dict[str, Any]:
    return {
        **core,
        field: _sha(core),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def _verify(value: dict[str, Any], schema: str, field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise BlueprintError("E_BLUEPRINT_SCHEMA", f"expected {schema}")
    expected = value.get(field)
    core = {
        key: item
        for key, item in value.items()
        if key not in {field, "generated_at", "path"}
    }
    if expected != _sha(core):
        raise BlueprintError("E_BLUEPRINT_TAMPERED", f"{field} does not match contents")
    return value


def retain_observation(
    *,
    source: str,
    source_digest: str,
    project: str,
    subject: str,
    classification: str,
    entities: Iterable[object] = (),
    tags: Iterable[object] = (),
    observed_at: str,
    summary: str,
) -> dict[str, Any]:
    """Retain a secret-free, provenance-bound observation for later recall."""
    if classification not in MEMORY_CLASSES:
        raise BlueprintError(
            "E_BLUEPRINT_CLASSIFICATION",
            "classification must be fact, unknown, or uncertain",
        )
    core = {
        "schema": MEMORY_SCHEMA,
        "stage": "bronze",
        "source": _text(source, "source", 120),
        "source_digest": _digest(source_digest, "source_digest"),
        "project": _text(project, "project", 120),
        "subject": _text(subject, "subject", 160),
        "classification": classification,
        "entities": _list(entities, "entities"),
        "tags": _list(tags, "tags"),
        "observed_at": _timestamp(observed_at),
        "summary": _text(summary, "summary", 512),
        "authority": {"execute": False, "promote": False, "approve": False},
        "claim_boundary": "Provenance-bound observation only; no truth, identity, provider, or current-build proof.",
    }
    return _seal(core, "memory_sha256")


def recall_observations(
    observations: Iterable[dict[str, Any]],
    *,
    project: str | None = None,
    query: str | None = None,
    tags: Iterable[object] = (),
    limit: int = 50,
) -> dict[str, Any]:
    """Recall bounded facts with keyword, entity/tag, and temporal ordering."""
    if not isinstance(limit, int) or not 1 <= limit <= MAX_OBSERVATIONS:
        raise BlueprintError("E_BLUEPRINT_LIMIT", "limit must be between 1 and 500")
    project_filter, query_terms, tag_filter = _recall_filters(project, query, tags)
    matches, invalid = _matching_observations(
        observations, project_filter, query_terms, tag_filter
    )
    matches.sort(
        key=lambda item: (item["observed_at"], item["memory_sha256"]), reverse=True
    )
    matches = matches[:limit]
    return {
        "schema": "factory.blueprint-memory-recall.v1",
        "marker": "BLUEPRINT_MEMORY_RECALLED",
        "matches": matches,
        "invalid_count": invalid,
        "query": {
            "project": project_filter,
            "terms": query_terms,
            "tags": sorted(tag_filter),
        },
        "authority": {"execute": False, "promote": False, "approve": False},
        "claim_boundary": "Recall is retrieval guidance only; it never mutates intent or proves the current implementation.",
    }


def _recall_filters(
    project: str | None, query: str | None, tags: Iterable[object]
) -> tuple[str | None, list[str], set[str]]:
    project_filter = (
        project.strip() if isinstance(project, str) and project.strip() else None
    )
    query_terms = (
        [term.casefold() for term in query.split() if term.strip()]
        if isinstance(query, str)
        else []
    )
    tag_filter = set(_list(tags, "tags"))
    return project_filter, query_terms, tag_filter


def _observation_matches(
    value: dict[str, Any],
    project_filter: str | None,
    query_terms: list[str],
    tag_filter: set[str],
) -> bool:
    haystack = " ".join(
        [value["subject"], value["summary"], *value["entities"], *value["tags"]]
    ).casefold()
    return not (
        (project_filter and value["project"] != project_filter)
        or (query_terms and not all(term in haystack for term in query_terms))
        or (tag_filter and not tag_filter.issubset(set(value["tags"])))
    )


def _matching_observations(
    observations: Iterable[dict[str, Any]],
    project_filter: str | None,
    query_terms: list[str],
    tag_filter: set[str],
) -> tuple[list[dict[str, Any]], int]:
    matches: list[dict[str, Any]] = []
    invalid = 0
    for item in observations:
        try:
            value = _verify(item, MEMORY_SCHEMA, "memory_sha256")
        except BlueprintError:
            invalid += 1
            continue
        if _observation_matches(value, project_filter, query_terms, tag_filter):
            matches.append(value)
    return matches, invalid


def reflect_observations(observations: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Produce deterministic counts and contradictions without an LLM call."""
    recalled = recall_observations(observations, limit=MAX_OBSERVATIONS)
    groups: dict[str, dict[str, Any]] = {}
    for item in recalled["matches"]:
        group = groups.setdefault(
            item["project"],
            {"project": item["project"], "count": 0, "classes": {}, "subjects": []},
        )
        group["count"] += 1
        group["classes"][item["classification"]] = (
            group["classes"].get(item["classification"], 0) + 1
        )
        if item["subject"] not in group["subjects"] and len(group["subjects"]) < 50:
            group["subjects"].append(item["subject"])
    return {
        "schema": "factory.blueprint-memory-reflection.v1",
        "marker": "BLUEPRINT_MEMORY_REFLECTED",
        "projects": sorted(groups.values(), key=lambda item: item["project"]),
        "input_count": len(recalled["matches"]),
        "invalid_count": recalled["invalid_count"],
        "model_invoked": False,
        "claim_boundary": "Deterministic aggregation only; no semantic model or mental model was inferred.",
    }


def librarian_promotion(
    observation: dict[str, Any],
    *,
    reviewer: str,
    stage: str,
    source_digest: str,
    contested: bool = False,
    feedback: str = "",
) -> dict[str, Any]:
    """Promote a Bronze observation through human-reviewed Silver/Gold."""
    _verify(observation, MEMORY_SCHEMA, "memory_sha256")
    reviewer = _text(reviewer, "reviewer", 120)
    _digest(source_digest, "source_digest")
    if source_digest != observation["source_digest"]:
        raise BlueprintError(
            "E_BLUEPRINT_SOURCE_DRIFT",
            "source digest changed since observation capture",
        )
    if stage not in {"silver", "gold", "contested"}:
        raise BlueprintError(
            "E_BLUEPRINT_STAGE", "stage must be silver, gold, or contested"
        )
    if stage == "gold" and contested:
        raise BlueprintError(
            "E_BLUEPRINT_CONTRADICTION",
            "contested knowledge cannot be promoted to gold",
        )
    core = {
        "schema": LIBRARIAN_SCHEMA,
        "stage": "contested" if contested else stage,
        "observation": {
            "memory_sha256": observation["memory_sha256"],
            "source_digest": source_digest,
        },
        "reviewer": reviewer,
        "feedback": _text(feedback, "feedback", 512) if feedback else "",
        "contested": contested,
        "human_approved": True,
        "authority": {"execute": False, "promote": False, "approve": False},
        "claim_boundary": "Curated knowledge is a reviewed reference; it never replaces fresh implementation evidence.",
    }
    return _seal(core, "librarian_sha256")


def signal_intent_proposal(signal: dict[str, Any], *, owner: str) -> dict[str, Any]:
    """Convert a verified local signal into an agent-proposed intent, never an auto-created task."""
    if not isinstance(signal, dict) or signal.get("schema") != "factory.signal.v1":
        raise BlueprintError(
            "E_BLUEPRINT_SIGNAL", "a normalized factory.signal.v1 receipt is required"
        )
    signal_digest = signal.get("signal_sha256")
    _digest(signal_digest, "signal_sha256")
    owner = _text(owner, "owner", 120)
    content = signal.get("content") if isinstance(signal.get("content"), dict) else {}
    title = _text(content.get("title"), "signal.title", 240)
    outcomes = (
        content.get("outcomes") if isinstance(content.get("outcomes"), list) else []
    )
    core = {
        "schema": INTENT_SCHEMA,
        "status": "agent_proposed",
        "title": f"Investigate: {title}",
        "problem": _text(content.get("body"), "signal.body", 512),
        "proposed_outcomes": _list(outcomes, "proposed_outcomes", 20),
        "source_signal": {
            "id": signal.get("id"),
            "sha256": signal_digest,
            "source": content.get("source"),
        },
        "owner": owner,
        "requires_human_confirmation": True,
        "authority": {"create_intent": False, "execute": False, "approve": False},
        "claim_boundary": "Agent-proposed intent only; no intent is sealed and no task is scheduled until a human confirms it.",
    }
    return _seal(core, "intent_sha256")


def access_profile(
    *,
    workspace: str,
    read_write: Iterable[object] = (),
    read_only: Iterable[object] = (),
    masked: Iterable[object] = (),
    runtime: str = "docker-compose",
) -> dict[str, Any]:
    """Create a fail-closed access declaration; it does not enforce isolation."""
    workspace = _text(workspace, "workspace", 240)
    runtime = _text(runtime, "runtime", 80)
    rw, ro, mask = map(
        lambda value: _list(value, "paths", 200), (read_write, read_only, masked)
    )
    if set(rw) & (set(ro) | set(mask)) or set(ro) & set(mask):
        raise BlueprintError(
            "E_BLUEPRINT_ACCESS_OVERLAP",
            "read-write, read-only, and masked paths must be disjoint",
        )
    core = {
        "schema": ACCESS_SCHEMA,
        "workspace": workspace,
        "runtime": runtime,
        "profiles": {"read_write": rw, "read_only": ro, "masked": mask},
        "enforcement": "declaration_only",
        "human_review_required": True,
        "authority": {"mount": False, "execute": False, "credential": False},
        "claim_boundary": "Access declaration only; Docker/kernel/egress enforcement must be supplied and independently verified by the selected runtime.",
    }
    return _seal(core, "access_sha256")


def team_plan(
    *,
    plan_id: str,
    intent_digest: str,
    workers: Iterable[dict[str, Any]],
    tasks: Iterable[dict[str, Any]],
    poll_interval_seconds: int = 60,
) -> dict[str, Any]:
    """Compile typed bot/subagent tasks without dispatching a worker."""
    plan_id = _text(plan_id, "plan_id", 120)
    _digest(intent_digest, "intent_digest")
    _validate_poll_interval(poll_interval_seconds)
    worker_rows, worker_ids = _worker_plan_rows(workers)
    task_rows, task_ids = _task_plan_rows(tasks, worker_ids)
    _validate_task_dependencies(task_rows, task_ids)
    core = {
        "schema": TEAM_SCHEMA,
        "plan_id": plan_id,
        "intent_digest": intent_digest,
        "workers": sorted(worker_rows, key=lambda item: item["id"]),
        "tasks": sorted(task_rows, key=lambda item: item["id"]),
        "poll_interval_seconds": poll_interval_seconds,
        "dispatcher": {"mode": "declarative", "started": False, "last_poll": None},
        "authority": {
            "dispatch": False,
            "execute": False,
            "merge": False,
            "approve": False,
        },
        "claim_boundary": "Typed plan only; no dispatcher, worker, model, branch, or merge action ran.",
    }
    return _seal(core, "plan_sha256")


def _validate_poll_interval(poll_interval_seconds: int) -> None:
    if (
        not isinstance(poll_interval_seconds, int)
        or not 5 <= poll_interval_seconds <= 3600
    ):
        raise BlueprintError(
            "E_BLUEPRINT_POLL", "poll_interval_seconds must be between 5 and 3600"
        )


def _worker_plan_rows(
    workers: Iterable[dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[str]]:
    worker_rows: list[dict[str, Any]] = []
    worker_ids: set[str] = set()
    for worker in workers:
        if not isinstance(worker, dict):
            raise BlueprintError("E_BLUEPRINT_WORKER", "worker must be an object")
        worker_id = _text(worker.get("id"), "worker.id", 80)
        if worker_id in worker_ids:
            raise BlueprintError("E_BLUEPRINT_WORKER", "worker ids must be unique")
        worker_ids.add(worker_id)
        tier = worker.get("model_tier", "workhorse")
        if tier not in MODEL_TIERS:
            raise BlueprintError("E_BLUEPRINT_WORKER", "worker.model_tier is invalid")
        worker_rows.append(
            {
                "id": worker_id,
                "kind": worker.get("kind", "subagent"),
                "model_tier": tier,
                "tools": _list(worker.get("tools", []), "worker.tools", 40),
            }
        )
    return worker_rows, worker_ids


def _task_plan_rows(
    tasks: Iterable[dict[str, Any]], worker_ids: set[str]
) -> tuple[list[dict[str, Any]], set[str]]:
    task_rows: list[dict[str, Any]] = []
    task_ids: set[str] = set()
    for task in tasks:
        if not isinstance(task, dict):
            raise BlueprintError("E_BLUEPRINT_TASK", "task must be an object")
        task_id = _text(task.get("id"), "task.id", 80)
        if task_id in task_ids:
            raise BlueprintError("E_BLUEPRINT_TASK", "task ids must be unique")
        task_ids.add(task_id)
        worker_id = _text(task.get("worker_id"), "task.worker_id", 80)
        if worker_id not in worker_ids:
            raise BlueprintError("E_BLUEPRINT_TASK", "task worker_id is not declared")
        deps = _list(task.get("dependencies", []), "task.dependencies", MAX_TASKS)
        task_rows.append(
            {
                "id": task_id,
                "worker_id": worker_id,
                "dependencies": deps,
                "state": "queued",
                "acceptance": _text(task.get("acceptance"), "task.acceptance", 240),
            }
        )
    return task_rows, task_ids


def _validate_task_dependencies(
    task_rows: list[dict[str, Any]], task_ids: set[str]
) -> None:
    if any(dep not in task_ids for task in task_rows for dep in task["dependencies"]):
        raise BlueprintError("E_BLUEPRINT_TASK", "task dependency is not declared")


def build_artifact_chain(
    *,
    intent: str,
    spec: str,
    plan: str,
    author: str,
    project: str,
    intent_status: str = "draft",
    files_changed: Iterable[object] = (),
    work_order: Iterable[object] = (),
    risks: Iterable[object] = (),
    proof_of_completion: Iterable[object] = (),
) -> dict[str, Any]:
    """Bind Intent, Spec, and Plan text into one drift-detectable chain."""
    if intent_status not in ARTIFACT_STATUSES:
        raise BlueprintError(
            "E_BLUEPRINT_STATUS", "intent_status must be draft, approved, or processed"
        )
    documents = {
        "intent": _document(intent, "intent"),
        "spec": _document(spec, "spec"),
        "plan": _document(plan, "plan"),
    }
    author = _text(author, "author", 120)
    project = _text(project, "project", 120)
    changed = _list(files_changed, "files_changed", 200)
    order = _list(work_order, "work_order", 200)
    risk_rows = _list(risks, "risks", 100)
    proof = _list(proof_of_completion, "proof_of_completion", 100)
    if not changed or not order or not proof:
        raise BlueprintError(
            "E_BLUEPRINT_CHAIN_INCOMPLETE",
            "files_changed, work_order, and proof_of_completion are required",
        )
    core = {
        "schema": ARTIFACT_SCHEMA,
        "project": project,
        "author": author,
        "intent_status": intent_status,
        "documents": {
            name: {"text": value, "sha256": _sha(value)}
            for name, value in documents.items()
        },
        "plan_contract": {
            "files_changed": changed,
            "work_order": order,
            "risks": risk_rows,
            "proof_of_completion": proof,
        },
        "authority": {
            "execute": False,
            "approve": False,
            "merge": False,
            "publish": False,
        },
        "claim_boundary": "Intent-to-plan lineage only; no code, test, branch, task, approval, or release action ran.",
        "lineage": "intent -> spec -> plan",
    }
    sealed = _seal(core, "chain_sha256")
    return sealed


def verify_artifact_chain(value: dict[str, Any]) -> dict[str, Any]:
    """Verify chain and document hashes without interpreting or executing them."""
    _verify(value, ARTIFACT_SCHEMA, "chain_sha256")
    documents = value.get("documents")
    if not isinstance(documents, dict) or set(documents) != {"intent", "spec", "plan"}:
        raise BlueprintError(
            "E_BLUEPRINT_CHAIN_SCHEMA", "documents must contain intent, spec, and plan"
        )
    drifted = [
        name
        for name, item in documents.items()
        if not isinstance(item, dict) or item.get("sha256") != _sha(item.get("text"))
    ]
    if drifted:
        raise BlueprintError(
            "E_BLUEPRINT_CHAIN_DRIFT",
            f"document hash drift: {', '.join(sorted(drifted))}",
        )
    return {
        "schema": ARTIFACT_SCHEMA,
        "marker": "BLUEPRINT_ARTIFACT_CHAIN_VERIFIED",
        "chain_sha256": value["chain_sha256"],
        "lineage": value.get("lineage"),
        "drifted": [],
        "authority": value.get("authority", {}),
        "claim_boundary": value.get("claim_boundary"),
    }


def blueprint_projection(root: Path) -> dict[str, Any]:
    """Summarize valid blueprint receipts under the local factory directory."""
    directory = Path(root).resolve() / ".factory" / "blueprint"
    counts: dict[str, int] = {}
    invalid = 0
    if directory.exists():
        for path in sorted(directory.glob("*.json"))[:500]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                schema = value.get("schema")
                field = {
                    MEMORY_SCHEMA: "memory_sha256",
                    LIBRARIAN_SCHEMA: "librarian_sha256",
                    INTENT_SCHEMA: "intent_sha256",
                    ACCESS_SCHEMA: "access_sha256",
                    TEAM_SCHEMA: "plan_sha256",
                    ARTIFACT_SCHEMA: "chain_sha256",
                }.get(schema)
                if not field:
                    raise BlueprintError(
                        "E_BLUEPRINT_SCHEMA", "unknown blueprint schema"
                    )
                _verify(value, schema, field)
                counts[schema] = counts.get(schema, 0) + 1
            except (OSError, json.JSONDecodeError, BlueprintError):
                invalid += 1
    return {
        "schema": BLUEPRINT_SCHEMA,
        "marker": "BLUEPRINT_STATUS_READ_ONLY",
        "directory": str(directory),
        "counts": dict(sorted(counts.items())),
        "invalid_count": invalid,
        "authority": {
            "execute": False,
            "dispatch": False,
            "approve": False,
            "publish": False,
        },
        "claim_boundary": "Local blueprint receipt inventory only; no memory, provider, runtime, task, or release action ran.",
    }
