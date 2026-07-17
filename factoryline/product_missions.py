"""Deterministic PRD-to-PR value compiler with governed mission handoffs."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
import hashlib
import json
import math
import os
import re
import tempfile

from .loop_passport import (
    DESTRUCTIVE_ACTIONS,
    build_loop_passport,
    default_manifest,
    verify_loop_passport,
)
from .failure_guidance import explain_failure
from .migration import verify_migration_readiness, verify_repository_context


PRODUCT_GRAPH_SCHEMA = "factory.product_graph.v1"
VALUE_SLICES_SCHEMA = "factory.value_slices.v1"
MISSION_SCHEMA = "factory.mission.v1"
PR_DRAFT_SCHEMA = "factory.pr_draft.v1"
OUTCOME_SCHEMA = "factory.outcome.v1"
MISSION_COMPLETION_SCHEMA = "factory.mission.completion.v1"
MISSION_VALIDATION_INPUT_SCHEMA = "factory.mission.validation-input.v1"
MISSION_DECISION_SCHEMA = "factory.mission.decision.v1"
MAX_PRD_BYTES = 65536
MAX_REQUIREMENTS = 500
MAX_SLICE_REQUIREMENTS = 5
MAX_NOTES = 4000
MAX_COMPLETION_CRITERIA = 200
MAX_COMPLETION_EVIDENCE = 100
EXECUTORS = frozenset({"manual", "codex", "copilot", "claude", "custom"})
EVIDENCE_CLASSES = frozenset({"measured", "observed", "modeled", "unknown"})
MISSION_DECISIONS = frozenset({"approved_execution", "deferred", "rejected"})
UX_STATES = (
    "loading", "empty", "error", "success", "recovery", "permission",
    "offline", "accessibility",
)
MISSION_MAXIMA = {
    "max_iterations": 5,
    "max_wall_seconds": 3600,
    "max_tokens": 100000,
    "max_cost_usd": 25.0,
}


class ProductMissionError(ValueError):
    """Closed, machine-readable failure from Product Missions."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.guidance = explain_failure(code, message)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_path(path: Path) -> str:
    return _sha_bytes(Path(path).read_bytes())


def _slug(value: str, fallback: str = "product") -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return (result or fallback)[:48]


def _load_json(path: Path, schema: str | None = None) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductMissionError("ARTIFACT_INVALID", f"cannot read JSON artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProductMissionError("ARTIFACT_INVALID", f"artifact must be a JSON object: {path}")
    if schema and value.get("schema") != schema:
        raise ProductMissionError("SCHEMA_UNSUPPORTED", f"expected {schema}: {path}")
    return value


def _atomic_text(path: Path, text: str, *, force: bool = False) -> Path:
    path = Path(path)
    data = text.encode("utf-8")
    if path.exists():
        if path.read_bytes() == data:
            return path
        if not force:
            raise ProductMissionError("ARTIFACT_EXISTS", f"refusing to replace {path}; use --force")
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    return path


def _atomic_json(path: Path, value: dict[str, Any], *, force: bool = False) -> Path:
    return _atomic_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n", force=force)


def _headings(text: str) -> dict[int, str]:
    current = "document"
    result: dict[int, str] = {}
    in_fence = False
    for number, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("```"):
            in_fence = not in_fence
        match = None if in_fence else re.match(r"^#{1,6}\s+(.+?)\s*$", line)
        if match:
            current = match.group(1).strip()
        result[number] = current
    return result


def _clean_bullet(line: str) -> str | None:
    match = re.match(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)(.+?)\s*$", line)
    if not match:
        return None
    value = re.sub(r"^\[[ xX]\]\s*", "", match.group(1)).strip()
    return value or None


def _stable_requirement_id(statement: str) -> str:
    explicit = re.match(r"^((?:REQ|FR|NFR)-[A-Za-z0-9_.-]+)\s*[:.-]?\s+", statement, re.I)
    if explicit:
        return explicit.group(1).upper()
    normalized = " ".join(statement.lower().split())
    return f"REQ-{_sha_bytes(normalized.encode('utf-8'))[:10].upper()}"


def _is_requirement(statement: str, section: str) -> bool:
    section_words = section.lower()
    if any(word in section_words for word in ("requirement", "feature", "user stor", "must")):
        return True
    return bool(re.search(r"\b(?:shall|must|as an?\s+.+?\s+i want|when\s+.+?\s+then)\b", statement, re.I))


def _requirement_kind(statement: str, section: str) -> str:
    value = f"{section} {statement}".lower()
    if any(word in value for word in ("security", "privacy", "permission", "encrypt", "auth")):
        return "trust"
    if any(word in value for word in ("latency", "performance", "availability", "reliability")):
        return "nonfunctional"
    if any(word in value for word in (
        "screen", "page", "button", "form", "user", "operator", "customer",
        "dashboard", "login", "mobile", "web",
    )):
        return "experience"
    return "functional"


def _extract_requirements(text: str) -> list[dict[str, Any]]:
    headings = _headings(text)
    requirements: list[dict[str, Any]] = []
    seen: set[str] = set()
    in_fence = False
    for number, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        statement = _clean_bullet(line)
        section = headings[number]
        if not statement or not _is_requirement(statement, section):
            continue
        normalized = " ".join(statement.split())
        requirement_id = _stable_requirement_id(normalized)
        if requirement_id in seen:
            continue
        seen.add(requirement_id)
        dependencies = {
            item.upper()
            for item in re.findall(r"\b(?:REQ|FR|NFR)-[A-Za-z0-9_.-]+\b", normalized, re.I)
        }
        dependencies.discard(requirement_id)
        kind = _requirement_kind(normalized, section)
        requirements.append({
            "id": requirement_id,
            "statement": normalized,
            "section": section,
            "source_line": number,
            "kind": kind,
            "user_facing": kind == "experience",
            "depends_on_requirements": sorted(dependencies),
        })
    if len(requirements) > MAX_REQUIREMENTS:
        raise ProductMissionError("REQUIREMENT_LIMIT", f"PRD contains more than {MAX_REQUIREMENTS} requirement atoms")
    return requirements


def _bullets_in_sections(text: str, names: Iterable[str]) -> list[str]:
    headings = _headings(text)
    needles = tuple(name.lower() for name in names)
    values: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not any(name in headings[number].lower() for name in needles):
            continue
        bullet = _clean_bullet(line)
        if bullet and bullet not in values:
            values.append(bullet)
    return values


def _extract_actors(text: str) -> list[str]:
    actors: list[str] = []
    for item in _bullets_in_sections(text, ("role", "actor", "persona", "user")):
        actor = item.split(":", 1)[0].strip()
        if 1 <= len(actor) <= 80 and actor not in actors:
            actors.append(actor)
    for match in re.finditer(r"\bAs an?\s+([^,\n]+)", text, re.I):
        actor = match.group(1).strip()
        if actor and actor not in actors:
            actors.append(actor)
    return actors


def _extract_product_facts(text: str) -> dict[str, list[str]]:
    """Extract only explicitly declared product facts from named PRD sections."""
    return {
        "jobs": _bullets_in_sections(text, ("job", "task", "responsibilit")),
        "pains": _bullets_in_sections(text, ("pain", "problem", "friction")),
        "desired_outcomes": _bullets_in_sections(text, ("desired outcome", "outcome", "goal")),
        "journeys": _bullets_in_sections(text, ("journey", "workflow", "user flow")),
        "business_rules": _bullets_in_sections(text, ("business rule", "policy", "decision rule")),
        "data_ownership": _bullets_in_sections(text, ("data ownership", "data owner", "retention", "export", "deletion")),
        "trust_boundaries": _bullets_in_sections(text, ("trust boundary", "trust", "security boundary", "privacy boundary")),
        "external_effects": _bullets_in_sections(text, ("external effect", "side effect", "message", "deploy", "publish", "payment")),
        "approval_requirements": _bullets_in_sections(text, ("approval", "human review", "authorization")),
        "success_events": _bullets_in_sections(text, ("success event", "outcome event", "metric event", "telemetry")),
    }


def _extract_acceptance(text: str) -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^\s*Scenario(?: Outline)?:\s*(.+?)\s*$", line, re.I)
        if match:
            current = {"id": f"AC-{len(scenarios) + 1:03d}", "title": match.group(1), "source_line": number, "steps": []}
            scenarios.append(current)
            continue
        if current and re.match(r"^\s*(?:Given|When|Then|And|But)\b", line):
            current["steps"].append(line.strip())
    return scenarios


def _ux_audit(text: str, requirements: list[dict[str, Any]]) -> dict[str, str]:
    user_facing = any(item["user_facing"] for item in requirements)
    lowered = text.lower()
    result = {}
    for state in UX_STATES:
        if not user_facing:
            result[state] = "not_applicable"
        else:
            result[state] = "declared" if re.search(rf"\b{re.escape(state)}\b", lowered) else "missing"
    return result


def _graph_mermaid(graph: dict[str, Any]) -> str:
    lines = ["flowchart LR", '    P["PRD source"] --> G["Product Graph"]']
    for index, requirement in enumerate(graph["requirements"], 1):
        label = requirement["id"].replace('"', "'")
        lines.append(f'    G --> R{index}["{label}"]')
    lines.extend(['    G --> X["Gap inventory"]', '    G --> U["UX state audit"]', '    G --> O["Outcome contract"]'])
    return "\n".join(lines) + "\n"


def _project_name(text: str, fallback: str) -> str:
    title = re.search(r"^#\s+(.+?)\s*$", text, re.M)
    return _slug(title.group(1) if title else fallback)


def _product_gaps(requirements: list[dict[str, Any]], acceptance: list[dict[str, Any]],
                  actors: list[str], outcomes: list[str], ux_states: dict[str, str],
                  facts: dict[str, list[str]]) -> list[dict[str, str]]:
    gaps: list[dict[str, str]] = []
    checks = (
        (not requirements, "REQUIREMENTS_MISSING", "blocking", "Add at least one testable requirement."),
        (not acceptance, "ACCEPTANCE_MISSING", "blocking", "Add at least one Gherkin Scenario."),
        (not actors, "ACTORS_MISSING", "advisory", "Name the user or operator roles."),
        (not outcomes, "OUTCOMES_MISSING", "advisory", "Declare a measurable product outcome."),
        (not facts["journeys"], "JOURNEYS_MISSING", "advisory", "Declare at least one end-to-end user journey."),
        (not facts["data_ownership"], "DATA_OWNERSHIP_MISSING", "advisory", "Declare who owns, exports, retains, and deletes product data."),
        (not facts["trust_boundaries"], "TRUST_BOUNDARIES_MISSING", "advisory", "Declare the product trust boundaries."),
        (not facts["approval_requirements"], "APPROVAL_REQUIREMENTS_MISSING", "advisory", "Declare which external or irreversible effects require approval."),
        (not facts["success_events"], "SUCCESS_EVENTS_MISSING", "advisory", "Declare measurable events that prove the product outcome."),
    )
    gaps.extend({"code": code, "severity": severity, "message": message} for missing, code, severity, message in checks if missing)
    gaps.extend({
        "code": f"UX_{state.upper()}_MISSING",
        "severity": "advisory",
        "message": f"Declare the {state} experience state.",
    } for state, status in ux_states.items() if status == "missing")
    return gaps


def compile_product_text(text: str, *, root: Path, source_name: str, project: str | None = None,
                         force: bool = False, bindings: dict[str, str] | None = None) -> dict[str, Any]:
    """Compile UTF-8 PRD text into a local Product Graph and gap inventory."""
    source_bytes = text.encode("utf-8")
    if not source_bytes or len(source_bytes) > MAX_PRD_BYTES:
        raise ProductMissionError("PRD_SIZE_INVALID", f"PRD must be 1-{MAX_PRD_BYTES} UTF-8 bytes")
    project_id = _slug(project) if project else _project_name(text, Path(source_name).stem)
    requirements = _extract_requirements(text)
    acceptance = _extract_acceptance(text)
    actors = _extract_actors(text)
    facts = _extract_product_facts(text)
    outcomes = _bullets_in_sections(text, ("outcome", "success", "goal", "metric"))
    constraints = _bullets_in_sections(text, ("constraint", "non-functional", "guardrail", "security", "privacy"))
    assumptions = _bullets_in_sections(text, ("assumption",))
    unknowns = _bullets_in_sections(text, ("unknown", "question", "open issue"))
    ux_states = _ux_audit(text, requirements)
    gaps = _product_gaps(requirements, acceptance, actors, outcomes, ux_states, facts)
    source_sha = _sha_bytes(source_bytes)
    core = {
        "schema": PRODUCT_GRAPH_SCHEMA,
        "project": project_id,
        "source": {"name": Path(source_name).name, "sha256": source_sha, "bytes": len(source_bytes)},
        "actors": actors,
        **facts,
        "requirements": requirements,
        "acceptance": acceptance,
        "outcomes": outcomes,
        "constraints": constraints,
        "assumptions": assumptions,
        "unknowns": unknowns,
        "bindings": dict(sorted((bindings or {}).items())),
        "ux_states": ux_states,
        "gaps": gaps,
        "status": "needs_input" if any(item["severity"] == "blocking" for item in gaps) else "ready",
        "markers": [
            "PRODUCT_GRAPH_BOUND", "REQUIREMENT_ATOMS_STABLE", "PRODUCT_GAPS_EXPOSED",
            "UX_STATES_AUDITED", "PRODUCT_TRUST_MODEL_BOUND", "PRODUCT_OUTCOME_EVENTS_BOUND",
        ],
    }
    graph = {**core, "graph_sha256": _sha_bytes(_canonical(core)), "generated_at": _now()}
    directory = Path(root).resolve() / ".factory" / "products" / project_id
    graph_path = directory / "product_graph.json"
    if graph_path.exists() and not force:
        existing = _load_json(graph_path, PRODUCT_GRAPH_SCHEMA)
        if existing.get("graph_sha256") == graph["graph_sha256"]:
            return {**existing, "path": str(graph_path), "mermaid": str(directory / "product_graph.mmd"), "idempotent": True}
        raise ProductMissionError("PRODUCT_GRAPH_EXISTS", f"product graph changed: {graph_path}; use --force")
    _atomic_text(directory / "source.md", text, force=force)
    _atomic_json(graph_path, graph, force=force)
    _atomic_text(directory / "product_graph.mmd", _graph_mermaid(graph), force=force)
    return {**graph, "path": str(graph_path), "mermaid": str(directory / "product_graph.mmd"), "idempotent": False}


def compile_product_prd(prd_path: Path, root: Path, project: str | None = None, force: bool = False) -> dict:
    """Compile one UTF-8 PRD file into a traceable Product Graph."""
    path = Path(prd_path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ProductMissionError("PRD_NOT_FOUND", f"cannot read PRD: {path}") from exc
    if len(data) > MAX_PRD_BYTES:
        raise ProductMissionError("PRD_SIZE_INVALID", f"PRD must be at most {MAX_PRD_BYTES} UTF-8 bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProductMissionError("PRD_ENCODING_INVALID", "PRD must be valid UTF-8") from exc
    return compile_product_text(text, root=root, source_name=str(path), project=project, force=force)


def verify_product_graph(graph_path: Path) -> dict[str, Any]:
    """Verify a Product Graph's own hash and its captured PRD source binding."""
    graph = _load_json(graph_path, PRODUCT_GRAPH_SCHEMA)
    core = {key: value for key, value in graph.items() if key not in {"graph_sha256", "generated_at"}}
    errors: list[str] = []
    if _sha_bytes(_canonical(core)) != graph.get("graph_sha256"):
        errors.append("product graph hash mismatch")
    source = Path(graph_path).resolve().parent / "source.md"
    if not source.exists():
        errors.append("captured PRD source is missing")
    elif _sha_path(source) != graph.get("source", {}).get("sha256"):
        errors.append("captured PRD source drift")
    return {
        "schema": "factory.product_graph.verification.v1",
        "valid": not errors,
        "status": "verified" if not errors else "invalid",
        "graph_sha256": graph.get("graph_sha256"),
        "errors": errors,
        "marker": "PRODUCT_GRAPH_BOUND" if not errors else "PRODUCT_GRAPH_DRIFT",
    }


_THEMES = (
    ("access", ("auth", "login", "permission", "role", "account")),
    ("onboarding", ("onboard", "signup", "setup", "first run")),
    ("trust", ("security", "privacy", "consent", "encrypt", "audit")),
    ("integration", ("webhook", "api", "connector", "import", "export", "sync")),
    ("insight", ("analytics", "report", "dashboard", "metric", "insight")),
    ("workflow", ("create", "update", "approve", "review", "schedule", "notify")),
)


def _theme(requirement: dict[str, Any]) -> str:
    text = requirement["statement"].lower()
    for name, words in _THEMES:
        if any(word in text for word in words):
            return name
    return "core"


def _slice_gates(requirements: list[dict[str, Any]]) -> list[str]:
    text = " ".join(item["statement"] for item in requirements).lower()
    gates = ["unit", "requirement-mutation", "receipt-trace"]
    if any(item["user_facing"] for item in requirements):
        gates.extend(["accessibility", "responsive-visual"])
    if any(word in text for word in ("auth", "permission", "security", "privacy", "secret")):
        gates.append("security")
    if any(word in text for word in ("api", "webhook", "connector", "external", "sync")):
        gates.append("integration")
    return gates


def _slice_risk(requirements: list[dict[str, Any]]) -> str:
    gates = _slice_gates(requirements)
    if "security" in gates or "integration" in gates:
        return "high"
    if "accessibility" in gates or len(requirements) > 3:
        return "medium"
    return "low"


def _slice_score(requirements: list[dict[str, Any]], graph: dict[str, Any]) -> dict[str, int]:
    """Score a slice with fixed, inspectable factors; higher priority ships first."""
    owned_ids = {item["id"] for item in requirements}
    dependent_count = sum(
        bool(owned_ids.intersection(item["depends_on_requirements"]))
        for item in graph["requirements"]
        if item["id"] not in owned_ids
    )
    risk = {"low": 1, "medium": 3, "high": 5}[_slice_risk(requirements)]
    gates = _slice_gates(requirements)
    factors = {
        "user_value": min(5, 1 + sum(item["user_facing"] for item in requirements) + bool(graph.get("outcomes"))),
        "uncertainty_retired": min(5, 1 + len(graph.get("unknowns", [])) + len(graph.get("assumptions", []))),
        "dependency_unlock": min(5, dependent_count),
        "security_change_risk": risk,
        "implementation_review_cost": min(5, len(requirements) + max(0, len(gates) - 3) // 2),
    }
    priority = (
        50
        + 8 * factors["user_value"]
        + 5 * factors["uncertainty_retired"]
        + 4 * factors["dependency_unlock"]
        - 6 * factors["security_change_risk"]
        - 5 * factors["implementation_review_cost"]
    )
    return {**factors, "priority": max(0, min(100, priority))}


def _slices_mermaid(plan: dict[str, Any]) -> str:
    lines = ["flowchart LR", '    G["Product Graph"] --> Q["Value slice queue"]']
    indexes = {item["id"]: number for number, item in enumerate(plan["slices"], 1)}
    for number, item in enumerate(plan["slices"], 1):
        lines.append(f'    Q --> S{number}["{item["id"]}: {item["theme"]}"]')
    for number, item in enumerate(plan["slices"], 1):
        for dependency in item["depends_on"]:
            if dependency in indexes:
                lines.append(f"    S{indexes[dependency]} --> S{number}")
    return "\n".join(lines) + "\n"


def _requirement_groups(requirements: list[dict[str, Any]], maximum: int) -> list[tuple[str, list[dict[str, Any]]]]:
    groups: list[tuple[str, list[dict[str, Any]]]] = []
    for requirement in requirements:
        name = _theme(requirement)
        if not groups or groups[-1][0] != name or len(groups[-1][1]) >= maximum:
            groups.append((name, []))
        groups[-1][1].append(requirement)
    return groups


def _value_slice(name: str, requirements: list[dict[str, Any]], graph: dict[str, Any]) -> dict[str, Any]:
    digest = _sha_bytes(_canonical([item["id"] for item in requirements]))[:8]
    return {
        "id": f"slice-{name}-{digest}",
        "theme": name,
        "requirement_ids": [item["id"] for item in requirements],
        "user_outcome": f"Deliver verified behavior for {requirements[0]['id']}: {requirements[0]['statement']}",
        "risk": _slice_risk(requirements),
        "score": _slice_score(requirements, graph),
        "gates": _slice_gates(requirements),
        "vertical_contract": {
            "ui": "implement declared UX states" if any(item["user_facing"] for item in requirements) else "not_applicable",
            "behavior": "implement every bound requirement",
            "api_data": "preserve declared data ownership and trust boundaries",
            "tests": ["unit", "acceptance", "requirement-mutation"],
            "observability": ["slice_started", "slice_completed", "slice_failed"],
            "rollback": "revert the slice commit and invalidate receipts derived from it",
        },
        "experience_contract": {
            "required_states": [state for state, status in graph["ux_states"].items() if status != "not_applicable"],
            "missing_states": [state for state, status in graph["ux_states"].items() if status == "missing"],
        },
        "acceptance_refs": [item["id"] for item in graph["acceptance"]],
        "depends_on": [],
    }


def _bind_slice_dependencies(slices: list[dict[str, Any]], requirements: list[dict[str, Any]]) -> None:
    owners = {requirement_id: item["id"] for item in slices for requirement_id in item["requirement_ids"]}
    requirements_by_id = {item["id"]: item for item in requirements}
    for item in slices:
        dependencies = {
            owners[dependency]
            for requirement_id in item["requirement_ids"]
            for dependency in requirements_by_id[requirement_id]["depends_on_requirements"]
            if dependency in owners and owners[dependency] != item["id"]
        }
        item["depends_on"] = sorted(dependencies)


def _validate_slice_coverage(slices: list[dict[str, Any]], requirements: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    assigned = [requirement for item in slices for requirement in item["requirement_ids"]]
    expected = [item["id"] for item in requirements]
    if len(assigned) != len(set(assigned)) or sorted(assigned) != sorted(expected):
        raise ProductMissionError("SLICE_COVERAGE_INVALID", "every requirement must be assigned exactly once")
    return assigned, expected


def plan_value_slices(graph_path: Path, root: Path, max_requirements: int = 3, force: bool = False) -> dict:
    """Assign every requirement exactly once to a deterministic vertical slice."""
    if max_requirements < 1 or max_requirements > MAX_SLICE_REQUIREMENTS:
        raise ProductMissionError("SLICE_BOUND_INVALID", f"max requirements must be 1-{MAX_SLICE_REQUIREMENTS}")
    graph = _load_json(graph_path, PRODUCT_GRAPH_SCHEMA)
    blocking = [item for item in graph.get("gaps", []) if item.get("severity") == "blocking"]
    if blocking:
        raise ProductMissionError("MISSION_BLOCKED_BY_PRODUCT_GAPS", ", ".join(item["code"] for item in blocking))
    slices = [_value_slice(name, requirements, graph) for name, requirements in _requirement_groups(graph["requirements"], max_requirements)]
    _bind_slice_dependencies(slices, graph["requirements"])
    slices.sort(key=lambda item: (-item["score"]["priority"], item["id"]))
    assigned, expected = _validate_slice_coverage(slices, graph["requirements"])
    core = {
        "schema": VALUE_SLICES_SCHEMA,
        "project": graph["project"],
        "graph_path": str(Path(graph_path).resolve()),
        "graph_sha256": graph["graph_sha256"],
        "slices": slices,
        "coverage": {
            "requirements": len(expected), "assigned": len(assigned),
            "deferred": [], "rejected": [], "unresolved": [], "complete": True,
        },
        "status": "ready",
        "markers": [
            "VALUE_SLICES_COVERAGE_COMPLETE", "DEPENDENCY_ORDER_DETERMINISTIC",
            "VALUE_SLICE_SCORE_DETERMINISTIC", "VERTICAL_SLICE_CONTRACT_BOUND",
        ],
    }
    plan = {**core, "slices_sha256": _sha_bytes(_canonical(core)), "generated_at": _now()}
    directory = Path(root).resolve() / ".factory" / "products" / graph["project"]
    path = directory / "value_slices.json"
    if path.exists() and not force:
        existing = _load_json(path, VALUE_SLICES_SCHEMA)
        if existing.get("slices_sha256") == plan["slices_sha256"]:
            return {**existing, "path": str(path), "mermaid": str(directory / "value_slices.mmd"), "idempotent": True}
        raise ProductMissionError("VALUE_SLICES_EXISTS", f"slice plan changed: {path}; use --force")
    _atomic_json(path, plan, force=force)
    _atomic_text(directory / "value_slices.mmd", _slices_mermaid(plan), force=force)
    return {**plan, "path": str(path), "mermaid": str(directory / "value_slices.mmd"), "idempotent": False}


def _bounded_budget(name: str, value: float | int | None) -> float | int:
    maximum = MISSION_MAXIMA[name]
    selected = maximum if value is None else value
    if isinstance(selected, bool) or not isinstance(selected, (int, float)) or selected < 0 or selected > maximum:
        raise ProductMissionError("MISSION_BUDGET_INVALID", f"{name} must be between 0 and {maximum}")
    if name in {"max_iterations", "max_wall_seconds"} and selected < 1:
        raise ProductMissionError("MISSION_BUDGET_INVALID", f"{name} must be at least 1")
    return selected


def _completion_criteria(selected: dict[str, Any]) -> list[dict[str, Any]]:
    criteria = [
        {
            "id": f"requirement:{item}", "kind": "requirement",
            "description": f"Prove {item}.", "verification_kind": "deterministic_test",
            "evidence_contract": {"local_hash_bound": True},
        }
        for item in selected["requirement_ids"]
    ]
    criteria.extend(
        {
            "id": f"acceptance:{item}", "kind": "acceptance",
            "description": f"Pass {item}.", "verification_kind": "deterministic_test",
            "evidence_contract": {"local_hash_bound": True},
        }
        for item in selected["acceptance_refs"]
    )
    criteria.extend(
        {
            "id": f"gate:{_slug(item)}", "kind": "gate",
            "description": f"Pass the {item} gate.", "verification_kind": "deterministic_tool",
            "evidence_contract": {"local_hash_bound": True},
        }
        for item in selected["gates"]
    )
    if selected["vertical_contract"]["ui"] != "not_applicable":
        criteria.append({
            "id": f"browser-flow:{selected['id']}",
            "kind": "browser_control",
            "description": f"Complete the primary user outcome for {selected['id']} in fewer than four interactions.",
            "verification_kind": "browser_control",
            "evidence_contract": {
                "schema": "factory.browser-flow.evidence.v1", "max_clicks": 3,
                "exact_url_match": True, "all_assertions_required": True,
                "screenshot_hashes_required": True,
            },
        })
    if not criteria or len(criteria) > MAX_COMPLETION_CRITERIA:
        raise ProductMissionError("NO_FINISH_CONTRACT", f"mission must define 1-{MAX_COMPLETION_CRITERIA} criteria")
    return criteria


def _mission_hypotheses(criteria: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": f"HYP-{number:03d}",
            "statement": f"The candidate satisfies {criterion['id']}.",
            "falsified_when": f"The bound {criterion['verification_kind']} evidence fails or is absent.",
            "criterion_id": criterion["id"],
            "status": "unverified",
        }
        for number, criterion in enumerate(criteria, 1)
    ]


def _routing_policy(risk: str) -> dict[str, Any]:
    creator, verifier = {
        "low": ("economy", "balanced"),
        "medium": ("balanced", "frontier"),
        "high": ("frontier", "frontier"),
    }[risk]
    return {
        "selector": "deterministic_slice_risk_v1",
        "creator_tier": creator,
        "verifier_tier": verifier,
        "provider_binding": "external_adapter_required",
        "quality_cost_override": "mission_owner_approval_required",
        "compaction": {
            "allowed": ["MISSION.md", "candidate_diff", "evidence_manifest", "hash_bound_attempt_summary"],
            "forbidden": ["creator_hidden_reasoning", "creator_transcript", "failed_attempt_history"],
        },
    }


def _mission_context(mission: dict[str, Any], selected: dict[str, Any]) -> str:
    requirements = "\n".join(f"- {item}" for item in selected["requirement_ids"])
    gates = "\n".join(f"- {item}" for item in selected["gates"])
    return f"""# Mission: {mission['id']}

Status: planned. Human approval is required before execution and promotion.

## User outcome

{selected['user_outcome']}

## Requirement IDs

{requirements}

## Required gates

{gates}

## Bound inputs

- Product Graph: `{mission['inputs']['graph_sha256']}`
- Value slices: `{mission['inputs']['slices_sha256']}`
- Loop Passport: `{mission['loop']['passport_sha256']}`

## Workspace and roles

- Worktree: `{mission['workspace_contract']['path']}`
- Branch: `{mission['workspace_contract']['branch']}`
- Builder writes only inside the approved workspace.
- Checker receives the candidate diff and evidence, not creator-private reasoning.
- UX reviewer may attach browser evidence but may not modify or promote the candidate.

This packet does not grant merge, publish, deploy, external-message, credential,
connector, or production-write authority.
"""


def _validated_slices(path: Path) -> dict[str, Any]:
    slices = _load_json(path, VALUE_SLICES_SCHEMA)
    core = {key: value for key, value in slices.items() if key not in {"slices_sha256", "generated_at"}}
    if _sha_bytes(_canonical(core)) != slices.get("slices_sha256"):
        raise ProductMissionError("MISSION_INPUT_DRIFT", "Value slice content hash is invalid")
    return slices


def _validated_graph(slices: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    graph_path = Path(slices["graph_path"])
    graph = _load_json(graph_path, PRODUCT_GRAPH_SCHEMA)
    core = {key: value for key, value in graph.items() if key not in {"graph_sha256", "generated_at"}}
    if _sha_bytes(_canonical(core)) != graph["graph_sha256"]:
        raise ProductMissionError("MISSION_INPUT_DRIFT", "Product Graph content hash is invalid")
    if slices.get("graph_sha256") != graph.get("graph_sha256"):
        raise ProductMissionError("MISSION_INPUT_DRIFT", "Value slices were compiled from a different Product Graph")
    return graph_path, graph


def _selected_slice(slices: dict[str, Any], slice_id: str) -> dict[str, Any]:
    selected = next((item for item in slices["slices"] if item["id"] == slice_id), None)
    if selected is None:
        raise ProductMissionError("SLICE_NOT_FOUND", f"slice not found: {slice_id}")
    return selected


def _existing_mission(path: Path, force: bool) -> dict[str, Any] | None:
    if not path.exists() or force:
        return None
    existing = _load_json(path, MISSION_SCHEMA)
    verification = verify_mission(path)
    if verification["valid"]:
        return {**existing, "path": str(path), "idempotent": True}
    raise ProductMissionError("MISSION_EXISTS", f"mission exists but is invalid: {path}; use --force")


def _optional_mission_inputs(root: Path, readiness_path: Path | None) -> tuple[dict[str, Any], list[str]]:
    inputs: dict[str, Any] = {}
    markers: list[str] = []
    if readiness_path is not None:
        readiness = verify_migration_readiness(Path(readiness_path))
        if not readiness["valid"] or not readiness["ready"]:
            raise ProductMissionError("MIGRATION_AGENT_NOT_READY", "; ".join(readiness["errors"]) or "every readiness category requires executable proof")
        inputs["migration_readiness"] = {"path": str(Path(readiness_path).resolve()), "sha256": _sha_path(Path(readiness_path))}
        markers.append("MIGRATION_AGENT_READY_BOUND")
    context = root.resolve() / ".factory" / "context" / "context-receipt.json"
    if context.is_file() and verify_repository_context(context)["valid"]:
        inputs["repository_context"] = {"path": str(context), "sha256": _sha_path(context)}
        markers.append("REPOSITORY_CONTEXT_BOUND")
    return inputs, markers


def _mission_markers(criteria: list[dict[str, Any]], extra: list[str]) -> list[str]:
    markers = [
        "MISSION_PASSPORT_BOUND", "MISSION_BUDGET_HARD", "EXTERNAL_EFFECTS_APPROVAL_REQUIRED",
        "CREATOR_VERIFIER_CONTEXT_WALL", "NO_FINISH_CONTRACT", "MISSION_SINGLE_WORKTREE_BOUND",
        "MISSION_ROLE_PERMISSIONS_SEPARATE", "MISSION_CONTEXT_MINIMIZED", "MISSION_HYPOTHESES_BOUND",
        "MISSION_FRESH_CONTEXT_ATTEMPTS", "MISSION_MODEL_ROUTING_BOUNDED",
    ]
    if any(item["verification_kind"] == "browser_control" for item in criteria):
        markers.append("BROWSER_CONTROL_CRITERION_BOUND")
    return markers + extra


def create_mission(slices_path: Path, slice_id: str, root: Path, owner: str, executor: str = "manual",
                   force: bool = False, max_iterations: int | None = None,
                   max_wall_seconds: int | None = None, max_tokens: int | None = None,
                   max_cost_usd: float | None = None, readiness_path: Path | None = None) -> dict:
    """Bind one approved slice into a supervised, budgeted mission contract."""
    if executor not in EXECUTORS:
        raise ProductMissionError("EXECUTOR_UNSUPPORTED", f"executor must be one of {', '.join(sorted(EXECUTORS))}")
    if not owner.strip():
        raise ProductMissionError("OWNER_REQUIRED", "mission owner is required")
    slices = _validated_slices(slices_path)
    graph_path, graph = _validated_graph(slices)
    selected = _selected_slice(slices, slice_id)
    mission_id = _slug(f"{slices['project']}-{slice_id}", "mission")[:64]
    directory = Path(root).resolve() / ".factory" / "missions" / mission_id
    workspace_path = Path(root).resolve() / ".factory" / "worktrees" / mission_id
    branch_name = f"codex/{mission_id}"[:120]
    mission_path = directory / "mission.json"
    existing = _existing_mission(mission_path, force)
    if existing is not None:
        return existing
    budget = {
        name: _bounded_budget(name, value)
        for name, value in {
            "max_iterations": max_iterations,
            "max_wall_seconds": max_wall_seconds,
            "max_tokens": max_tokens,
            "max_cost_usd": max_cost_usd,
        }.items()
    }
    loop_manifest = default_manifest(mission_id, owner)
    loop_manifest.update({
        "autonomy": "supervised",
        "workspace": {"mode": "isolated", "allowed_paths": ["."], "network": "deny"},
        "capabilities": {"skills": [f"executor:{executor}"], "connectors": [], "actions": ["read_repository", "write_workspace", "execute_tests"]},
        "budgets": budget,
        "validators": {
            "pre": ["product_graph_complete", "slice_coverage_complete"],
            "post": ["tests", "requirement_coverage", "receipt_trace"],
            "invariant": ["no_unapproved_promotion", "hash_bound_sources"],
        },
        "approvals": {
            "required_for": sorted(DESTRUCTIVE_ACTIONS | {"external_message", "credential", "connector_grant"}),
            "distinct_approver": True,
            "expires_minutes": 60,
        },
    })
    loop_path = directory / "loop.manifest.json"
    _atomic_json(loop_path, loop_manifest, force=force)
    passport = build_loop_passport(Path(root), loop_path)
    loop = {
        "manifest_path": str(loop_path.resolve()),
        "manifest_sha256": _sha_path(loop_path),
        "passport_path": passport["paths"]["json"],
        "passport_sha256": passport["passport_sha256"],
        "verdict": passport["verdict"],
    }
    criteria = _completion_criteria(selected)
    inputs = {
        "graph_path": str(graph_path.resolve()),
        "graph_file_sha256": _sha_path(graph_path),
        "graph_sha256": graph["graph_sha256"],
        "slices_path": str(Path(slices_path).resolve()),
        "slices_file_sha256": _sha_path(slices_path),
        "slices_sha256": slices["slices_sha256"],
    }
    optional_inputs, optional_markers = _optional_mission_inputs(Path(root), readiness_path)
    inputs.update(optional_inputs)
    markers = _mission_markers(criteria, optional_markers)
    core = {
        "schema": MISSION_SCHEMA,
        "id": mission_id,
        "project": slices["project"],
        "slice_id": slice_id,
        "owner": owner.strip(),
        "executor": executor,
        "status": "planned",
        "approval_state": "required_before_execution",
        "inputs": inputs,
        "slice": selected,
        "workspace_contract": {
            "mode": "worktree",
            "branch": branch_name,
            "path": str(workspace_path),
            "count": 1,
            "provisioning_state": "requires_execution_approval",
        },
        "context_packet": {
            "requirement_ids": selected["requirement_ids"],
            "requirements": [
                {"id": item["id"], "statement": item["statement"], "kind": item["kind"]}
                for item in graph["requirements"]
                if item["id"] in selected["requirement_ids"]
            ],
            "acceptance_refs": selected["acceptance_refs"],
            "allowed_paths": ["."],
            "excluded_context": ["unrelated_prd_sections", "creator_private_reasoning", "unrelated_repository_history"],
        },
        "loop": loop,
        "budgets": budget,
        "role_permissions": {
            "builder": {
                "can": ["read_context_packet", "write_workspace", "run_approved_tools"],
                "cannot": ["approve_own_work", "merge", "deploy", "publish", "external_message"],
            },
            "checker": {
                "can": ["read_candidate_diff", "run_validators", "attach_evidence"],
                "cannot": ["read_creator_private_reasoning", "modify_candidate", "merge", "deploy", "publish"],
            },
            "ux_reviewer": {
                "can": ["read_declared_ux_states", "run_browser_checks", "attach_screenshots"],
                "cannot": ["modify_candidate", "approve_release", "deploy", "publish"],
            },
        },
        "orchestration": {
            "pattern": "creator_verifier",
            "creator": {"executor": executor, "reasoning_profile": "balanced_generation", "inputs": ["MISSION.md", "repository", "approved_tools"]},
            "verifier": {"executor": "independent", "reasoning_profile": "independent_high_reasoning", "inputs": ["mission.json", "candidate_diff", "evidence_manifest"]},
            "context_wall": {
                "required": True,
                "verifier_forbidden_inputs": ["creator_scratchpad", "creator_transcript", "creator_hidden_reasoning", "failed_attempt_history"],
                "same_identity_allowed": False,
            },
            "attempt_policy": {
                "fresh_session_required": True,
                "max_attempts": budget["max_iterations"],
                "prior_attempt_context_allowed": False,
                "attempt_summary": "hash_bound_outcomes_only",
                "runtime_enforcement": "external_adapter_must_attest",
            },
            "routing_policy": _routing_policy(selected["risk"]),
        },
        "completion_contract": {
            "all_required": True,
            "criteria": criteria,
            "hypotheses": _mission_hypotheses(criteria),
            "independent_verifier_required": True,
            "evidence_required_per_criterion": True,
            "completion_receipt_required": True,
        },
        "authority": {"execute": "human_approval", "merge": False, "publish": False, "deploy": False, "external_message": False},
        "markers": markers,
    }
    mission = {**core, "mission_sha256": _sha_bytes(_canonical(core)), "generated_at": _now()}
    _atomic_json(mission_path, mission, force=force)
    context_path = directory / "MISSION.md"
    _atomic_text(context_path, _mission_context(mission, selected), force=force)
    return {**mission, "path": str(mission_path), "context": str(context_path), "idempotent": False}


def _verify_primary_input(mission: dict[str, Any], name: str) -> list[str]:
    path = Path(mission["inputs"][f"{name}_path"])
    if not path.exists():
        return [f"missing {name} input"]
    if _sha_path(path) != mission["inputs"][f"{name}_file_sha256"]:
        return [f"{name} input drift"]
    return []


def _verify_optional_input(mission: dict[str, Any], name: str) -> list[str]:
    bound = mission.get("inputs", {}).get(name)
    if not bound:
        return []
    path = Path(bound["path"])
    if not path.is_file() or _sha_path(path) != bound["sha256"]:
        return [f"{name} input drift"]
    if name == "migration_readiness":
        check = verify_migration_readiness(path)
        return [] if check["valid"] and check["ready"] else ["migration readiness is no longer verified and ready"]
    return [] if verify_repository_context(path)["valid"] else ["repository context is no longer verified"]


def _verify_mission_passport(mission: dict[str, Any]) -> list[str]:
    path = Path(mission["loop"]["passport_path"])
    if not path.exists():
        return ["missing Loop Passport"]
    result = verify_loop_passport(path)
    if not result["valid"] or result["passport_sha256"] != mission["loop"]["passport_sha256"]:
        return ["Loop Passport invalid or changed"]
    return []


def verify_mission(mission_path: Path) -> dict:
    """Verify mission identity, source artifacts, and Loop Passport without execution."""
    mission = _load_json(mission_path, MISSION_SCHEMA)
    core = {key: value for key, value in mission.items() if key not in {"mission_sha256", "generated_at", "path", "context", "idempotent"}}
    errors = [] if _sha_bytes(_canonical(core)) == mission.get("mission_sha256") else ["mission hash mismatch"]
    for name in ("graph", "slices"):
        errors.extend(_verify_primary_input(mission, name))
    for name in ("migration_readiness", "repository_context"):
        errors.extend(_verify_optional_input(mission, name))
    errors.extend(_verify_mission_passport(mission))
    return {
        "schema": "factory.mission.verification.v1",
        "mission_id": mission.get("id"),
        "valid": not errors,
        "status": "verified" if not errors else "invalid",
        "marker": "MISSION_VERIFIED" if not errors else "MISSION_INPUT_DRIFT",
        "errors": errors,
        "authority": "verification only; no execution or promotion authority",
    }


def decide_mission(mission_path: Path, root: Path, *, owner: str, decision: str,
                   rationale: str, force: bool = False) -> dict[str, Any]:
    """Record one owner decision without granting downstream release authority."""
    verification = verify_mission(mission_path)
    if not verification["valid"]:
        raise ProductMissionError("MISSION_INPUT_DRIFT", "; ".join(verification["errors"]))
    mission = _load_json(mission_path, MISSION_SCHEMA)
    if owner.strip() != mission["owner"]:
        raise ProductMissionError("MISSION_DECISION_OWNER_MISMATCH", "decision owner must match the mission owner")
    if decision not in MISSION_DECISIONS:
        raise ProductMissionError("DECISION_INVALID", f"decision must be one of {', '.join(sorted(MISSION_DECISIONS))}")
    if not rationale.strip() or len(rationale) > MAX_NOTES:
        raise ProductMissionError("RATIONALE_INVALID", f"rationale is required and limited to {MAX_NOTES} characters")
    core = {
        "schema": MISSION_DECISION_SCHEMA,
        "mission": {
            "path": str(Path(mission_path).resolve()),
            "file_sha256": _sha_path(mission_path),
            "mission_sha256": mission["mission_sha256"],
        },
        "mission_id": mission["id"],
        "owner": owner.strip(),
        "decision": decision,
        "rationale": rationale.strip(),
        "execution_authorized": decision == "approved_execution",
        "authority": {
            "execute_bounded_mission": decision == "approved_execution",
            "merge": False,
            "publish": False,
            "deploy": False,
            "external_message": False,
            "connector_grant": False,
            "credential_access": False,
        },
        "markers": ["MISSION_EXECUTION_APPROVAL_BOUND", "EXTERNAL_EFFECTS_APPROVAL_REQUIRED"],
    }
    receipt = {**core, "decision_sha256": _sha_bytes(_canonical(core)), "generated_at": _now()}
    path = Path(root).resolve() / ".factory" / "missions" / mission["id"] / "execution_decision.json"
    _atomic_json(path, receipt, force=force)
    return {**receipt, "path": str(path)}


def _evidence(root: Path, paths: list[Path]) -> list[dict[str, Any]]:
    root = Path(root).resolve()
    result = []
    for value in paths:
        path = Path(value).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ProductMissionError("EVIDENCE_OUTSIDE_ROOT", f"evidence must be beneath {root}: {path}") from exc
        if not path.is_file():
            raise ProductMissionError("EVIDENCE_MISSING", f"evidence file not found: {path}")
        result.append({"path": str(path), "sha256": _sha_path(path), "bytes": path.stat().st_size})
    return result


def _review_evidence(evidence: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    categories = {name: [] for name in ("screenshots", "responsive", "accessibility", "tests", "mutations", "gates", "traces")}
    for item in evidence:
        name = Path(item["path"]).name.lower()
        if any(word in name for word in ("screenshot", ".png", ".jpg", ".jpeg", ".webp")):
            categories["screenshots"].append(item)
        if any(word in name for word in ("responsive", "mobile", "viewport")):
            categories["responsive"].append(item)
        if any(word in name for word in ("a11y", "accessibility", "axe")):
            categories["accessibility"].append(item)
        if any(word in name for word in ("test", "pytest", "junit")):
            categories["tests"].append(item)
        if any(word in name for word in ("mutation", "challenge")):
            categories["mutations"].append(item)
        if any(word in name for word in ("gate", "verify", "receipt")):
            categories["gates"].append(item)
        if any(word in name for word in ("trace", "passport")):
            categories["traces"].append(item)
    return categories


def _validation_manifest(path: Path, root: Path) -> tuple[dict[str, Any], Path]:
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(Path(root).resolve())
    except ValueError as exc:
        raise ProductMissionError("VALIDATION_OUTSIDE_ROOT", f"validation manifest must be beneath {Path(root).resolve()}") from exc
    value = _load_json(resolved, MISSION_VALIDATION_INPUT_SCHEMA)
    for field in ("creator_id", "verifier_id"):
        if not isinstance(value.get(field), str) or not value[field].strip() or len(value[field]) > 120:
            raise ProductMissionError("NO_FINISH_CONTRACT", f"{field} is required and limited to 120 characters")
    return value, resolved


def _validate_context_wall(mission: dict[str, Any], manifest: dict[str, Any]) -> None:
    if manifest["creator_id"].strip() == manifest["verifier_id"].strip():
        raise ProductMissionError("VERIFIER_IDENTITY_DISTINCT", "creator and verifier identities must differ")
    contexts = manifest.get("verifier_context")
    required = {"mission.json", "candidate_diff", "evidence_manifest"}
    allowed = required | {"test_output", "browser_artifact", "architecture_receipt"}
    forbidden = set(mission["orchestration"]["context_wall"]["verifier_forbidden_inputs"])
    if (
        not isinstance(contexts, list)
        or not all(isinstance(item, str) for item in contexts)
        or not required.issubset(contexts)
        or not set(contexts).issubset(allowed)
        or forbidden.intersection(contexts)
    ):
        raise ProductMissionError("CREATOR_VERIFIER_CONTEXT_WALL", "verifier context must contain only review inputs and exclude creator-private context")


def _browser_flow_artifacts(mission: dict[str, Any], criterion: dict[str, Any], evidence_path: Path,
                            verifier_id: str, root: Path) -> tuple[list[Path], dict[str, Any]]:
    evidence_path = evidence_path.resolve()
    try:
        evidence_path.relative_to(Path(root).resolve())
    except ValueError as exc:
        raise ProductMissionError("BROWSER_FLOW_INVALID", "browser evidence must be beneath the mission root") from exc
    evidence = _load_json(evidence_path, "factory.browser-flow.evidence.v1")
    contract = criterion["evidence_contract"]
    errors = []
    if evidence.get("mission_id") != mission["id"] or evidence.get("criterion_id") != criterion["id"]:
        errors.append("mission or criterion id mismatch")
    if evidence.get("verifier_id") != verifier_id:
        errors.append("browser verifier must match the independent validation manifest")
    expected = evidence.get("expected_url")
    observed = evidence.get("observed_url")
    if not isinstance(expected, str) or not expected or observed != expected:
        errors.append("observed URL does not exactly match the declared expected URL")
    clicks = evidence.get("clicks")
    steps = evidence.get("steps")
    if isinstance(clicks, bool) or not isinstance(clicks, int) or clicks < 0 or clicks > contract["max_clicks"]:
        errors.append(f"click count must be between 0 and {contract['max_clicks']}")
    if not isinstance(steps, list) or not isinstance(clicks, int) or len(steps) != clicks or any(not isinstance(item, dict) or item.get("passed") is not True for item in steps):
        errors.append("every counted browser interaction must have one passing step")
    assertions = evidence.get("assertions")
    if not isinstance(assertions, list) or not assertions or any(not isinstance(item, dict) or item.get("passed") is not True for item in assertions):
        errors.append("every declared browser assertion must pass")
    artifacts = evidence.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("at least one screenshot or browser artifact is required")
        artifacts = []
    resolved = []
    for value in artifacts:
        if not isinstance(value, str) or not value.strip():
            errors.append("browser artifact paths must be non-empty strings")
            continue
        path = Path(value) if Path(value).is_absolute() else Path(root).resolve() / value
        try:
            path.resolve().relative_to(Path(root).resolve())
        except ValueError:
            errors.append(f"browser artifact is outside the mission root: {path}")
            continue
        if not path.is_file():
            errors.append(f"browser artifact is missing: {path}")
        else:
            resolved.append(path.resolve())
    if errors:
        raise ProductMissionError("BROWSER_FLOW_INVALID", "; ".join(errors))
    return resolved, {
        "expected_url": expected, "observed_url": observed, "clicks": clicks,
        "max_clicks": contract["max_clicks"], "assertions": len(assertions),
    }


def _validated_completion_results(mission: dict[str, Any], manifest: dict[str, Any], root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    criteria_by_id = {item["id"]: item for item in mission["completion_contract"]["criteria"]}
    expected = list(criteria_by_id)
    results = manifest.get("criteria")
    if not isinstance(results, list) or not 1 <= len(results) <= MAX_COMPLETION_CRITERIA:
        raise ProductMissionError("NO_FINISH_CONTRACT", f"validation must contain 1-{MAX_COMPLETION_CRITERIA} criteria")
    ids = [item.get("id") for item in results if isinstance(item, dict)]
    if len(ids) != len(results) or len(ids) != len(set(ids)) or sorted(ids) != sorted(expected):
        raise ProductMissionError("NO_FINISH_CONTRACT", "validation must cover every completion criterion exactly once")
    evidence_paths: list[Path] = []
    normalized = []
    for item in results:
        paths = item.get("evidence")
        if (
            item.get("passed") is not True
            or not isinstance(paths, list)
            or not paths
            or not all(isinstance(value, str) and value.strip() for value in paths)
        ):
            raise ProductMissionError("NO_FINISH_CONTRACT", f"criterion {item.get('id')} must pass with evidence")
        resolved = [Path(value) if Path(value).is_absolute() else Path(root).resolve() / value for value in paths]
        browser_summary = None
        if criteria_by_id[item["id"]].get("verification_kind") == "browser_control":
            if len(resolved) != 1:
                raise ProductMissionError("BROWSER_FLOW_INVALID", "browser-control criteria require exactly one structured evidence receipt")
            artifacts, browser_summary = _browser_flow_artifacts(
                mission, criteria_by_id[item["id"]], resolved[0], manifest["verifier_id"].strip(), root,
            )
            evidence_paths.extend(artifacts)
        evidence_paths.extend(resolved)
        normalized_item = {"id": item["id"], "passed": True, "evidence": [str(path.resolve()) for path in resolved]}
        if browser_summary is not None:
            normalized_item["browser_flow"] = browser_summary
        normalized.append(normalized_item)
    unique = list(dict.fromkeys(path.resolve() for path in evidence_paths))
    if len(unique) > MAX_COMPLETION_EVIDENCE:
        raise ProductMissionError("NO_FINISH_CONTRACT", f"completion evidence is limited to {MAX_COMPLETION_EVIDENCE} files")
    return normalized, _evidence(Path(root), unique)


def close_mission(mission_path: Path, validation_path: Path, root: Path, *, force: bool = False) -> dict[str, Any]:
    """Write completion only after fresh-context, exact-coverage verification."""
    mission_check = verify_mission(mission_path)
    if not mission_check["valid"]:
        raise ProductMissionError("MISSION_INPUT_DRIFT", "; ".join(mission_check["errors"]))
    mission = _load_json(mission_path, MISSION_SCHEMA)
    manifest, resolved_validation = _validation_manifest(validation_path, root)
    _validate_context_wall(mission, manifest)
    results, evidence = _validated_completion_results(mission, manifest, root)
    core = {
        "schema": MISSION_COMPLETION_SCHEMA,
        "mission": {"path": str(Path(mission_path).resolve()), "sha256": _sha_path(mission_path), "mission_sha256": mission["mission_sha256"]},
        "validation": {"path": str(resolved_validation), "sha256": _sha_path(resolved_validation)},
        "creator_id": manifest["creator_id"].strip(),
        "verifier_id": manifest["verifier_id"].strip(),
        "verifier_context": manifest["verifier_context"],
        "criteria": results,
        "evidence": evidence,
        "status": "completed",
        "authority": {"merge": False, "publish": False, "deploy": False},
        "markers": ["CREATOR_VERIFIER_CONTEXT_WALL", "VERIFIER_IDENTITY_DISTINCT", "NO_FINISH_CONTRACT", "VALIDATION_EVIDENCE_BOUND"],
    }
    receipt = {**core, "completion_sha256": _sha_bytes(_canonical(core)), "generated_at": _now()}
    path = Path(mission_path).resolve().parent / "completion.json"
    _atomic_json(path, receipt, force=force)
    return {**receipt, "path": str(path)}


def _bound_file_error(item: dict[str, Any], label: str) -> str | None:
    path = Path(item["path"])
    if not path.exists() or _sha_path(path) != item["sha256"]:
        return f"{label} drift: {path}" if label == "evidence" else f"{label} input drift"
    return None


def _completion_errors(receipt: dict[str, Any]) -> list[str]:
    core = {key: value for key, value in receipt.items() if key not in {"completion_sha256", "generated_at", "path"}}
    errors = []
    if _sha_bytes(_canonical(core)) != receipt.get("completion_sha256"):
        errors.append("completion receipt hash mismatch")
    errors.extend(
        error
        for name in ("mission", "validation")
        if (error := _bound_file_error(receipt[name], name))
    )
    errors.extend(
        error
        for item in receipt.get("evidence", [])
        if (error := _bound_file_error(item, "evidence"))
    )
    mission_path = Path(receipt["mission"]["path"])
    if mission_path.exists() and not verify_mission(mission_path)["valid"]:
        errors.append("mission no longer verifies")
    return errors


def verify_mission_completion(completion_path: Path) -> dict[str, Any]:
    """Verify completion, validation, mission, and every evidence file hash."""
    receipt = _load_json(completion_path, MISSION_COMPLETION_SCHEMA)
    errors = _completion_errors(receipt)
    result = {
        "schema": "factory.mission.completion.verification.v1",
        "valid": not errors,
        "status": "verified" if not errors else "invalid",
        "marker": "MISSION_COMPLETION_VERIFIED" if not errors else "MISSION_COMPLETION_DRIFT",
        "errors": errors,
        "authority": "completion verification only; no merge or deployment authority",
    }
    if errors:
        result["failure"] = explain_failure("MISSION_COMPLETION_DRIFT", "; ".join(errors), errors=errors)
    return result


def _pr_markdown(draft: dict[str, Any]) -> str:
    requirements = "\n".join(f"- [ ] `{item}`" for item in draft["requirements"])
    evidence = "\n".join(f"- `{item['path']}` sha256 `{item['sha256']}`" for item in draft["evidence"]) or "- No evidence attached yet."
    risks = "\n".join(f"- {item}" for item in draft["risks"])
    unknowns = "\n".join(f"- {item}" for item in draft["unproven_claims"])
    changes = "\n".join(f"- {item}" for item in draft["architecture_changes"] + draft["data_contract_changes"])
    proof = "\n".join(
        f"- {name}: {len(items)} attached"
        for name, items in draft["review_evidence"].items()
    )
    return f"""# {draft['title']}

## User value

{draft['user_outcome']}

- Before: {draft['before_after']['before']}
- After: {draft['before_after']['after']}

## Requirement coverage

{requirements}

## Evidence

{evidence}

## Architecture and data contracts

{changes}

## Review proof inventory

{proof}

## Budget and trace

- Budget: {draft['budget_consumption']['status']}
- Trace links: {len(draft['trace_links'])}

## Risk and rollback

{risks}
- Rollback: revert this slice PR and invalidate its mission receipts.

## Outcome events

- Record activation, task completion, or another PRD-declared outcome after release.

## Unproven claims

{unknowns}

## Authority

Draft only. This package does not approve merge, release, publish, or deploy.
"""


def draft_pr(mission_path: Path, root: Path, evidence_paths: list[Path] | None = None, force: bool = False) -> dict:
    """Create a reviewer-ready, evidence-linked draft without remote side effects."""
    verification = verify_mission(mission_path)
    if not verification["valid"]:
        raise ProductMissionError("MISSION_INPUT_DRIFT", "; ".join(verification["errors"]))
    mission = _load_json(mission_path, MISSION_SCHEMA)
    graph = _load_json(Path(mission["inputs"]["graph_path"]), PRODUCT_GRAPH_SCHEMA)
    evidence = _evidence(root, evidence_paths or [])
    review_evidence = _review_evidence(evidence)
    missing_states = mission["slice"]["experience_contract"]["missing_states"]
    core = {
        "schema": PR_DRAFT_SCHEMA,
        "mission_id": mission["id"],
        "mission_sha256": mission["mission_sha256"],
        "title": f"Deliver {mission['slice_id']}",
        "user_outcome": mission["slice"]["user_outcome"],
        "before_after": {
            "before": "The PRD outcome is not yet proven by the candidate implementation.",
            "after": mission["slice"]["user_outcome"],
        },
        "requirements": mission["slice"]["requirement_ids"],
        "requirement_coverage": {
            "added": mission["slice"]["requirement_ids"],
            "changed": [], "deferred": [], "rejected": [], "invalidated": [],
        },
        "acceptance_refs": mission["slice"]["acceptance_refs"],
        "evidence": evidence,
        "review_evidence": review_evidence,
        "architecture_changes": [
            f"Worktree {mission['workspace_contract']['branch']} implements one vertical slice.",
            f"Required gates: {', '.join(mission['slice']['gates'])}.",
        ],
        "data_contract_changes": [
            f"Data ownership declarations: {len(graph.get('data_ownership', []))}.",
            f"Trust boundaries: {len(graph.get('trust_boundaries', []))}.",
            f"External effects remain approval-bound: {len(graph.get('external_effects', []))} declared.",
        ],
        "budget_consumption": {
            "status": "unreported" if not evidence else "evidence_attached_usage_not_inferred",
            "limits": mission["budgets"],
            "measured": None,
        },
        "trace_links": review_evidence["traces"],
        "risks": [
            f"Factory risk class: {mission['slice']['risk']}",
            f"Required gates: {', '.join(mission['slice']['gates'])}",
            "Security and external-effect approval remain independent of this draft.",
        ],
        "rollout": "Use the selected deployment profile only after independent release approval and canary evidence.",
        "rollback": "Revert the slice PR and invalidate mission receipts derived from its commit.",
        "outcome_events": graph.get("success_events") or ["prd_declared_metric_missing"],
        "unproven_claims": (
            [f"UX state not declared in PRD: {state}" for state in missing_states]
            + (["No implementation evidence attached."] if not evidence else [])
            + [f"No {name} evidence attached." for name, items in review_evidence.items() if not items]
        ),
        "authority": {"draft_only": True, "merge": False, "release": False, "publish": False, "deploy": False},
        "markers": [
            "PR_EVIDENCE_LINKED", "PR_DRAFT_NO_MERGE_AUTHORITY",
            "PR_REVIEW_PACKAGE_COMPLETE", "PR_UNPROVEN_CLAIMS_EXPLICIT",
        ],
    }
    draft = {**core, "draft_sha256": _sha_bytes(_canonical(core)), "generated_at": _now()}
    directory = Path(root).resolve() / ".factory" / "missions" / mission["id"]
    json_path = directory / "pr_draft.json"
    md_path = directory / "PR_DRAFT.md"
    markdown = _pr_markdown(draft)
    if not force:
        for path, content in ((json_path, json.dumps(draft, indent=2, sort_keys=True) + "\n"), (md_path, markdown)):
            if path.exists() and path.read_text(encoding="utf-8") != content:
                raise ProductMissionError("OUTPUT_EXISTS", f"refusing to replace existing output: {path}")
    _atomic_json(json_path, draft, force=force)
    _atomic_text(md_path, markdown, force=force)
    return {**draft, "path": str(json_path), "markdown": str(md_path)}


def _validate_outcome(metric: str, value: float | None, target: float | None,
                      evidence_class: str, source: str | None, notes: str) -> None:
    if evidence_class not in EVIDENCE_CLASSES:
        raise ProductMissionError("EVIDENCE_CLASS_INVALID", f"evidence class must be one of {', '.join(sorted(EVIDENCE_CLASSES))}")
    if not metric.strip() or len(metric) > 120:
        raise ProductMissionError("METRIC_INVALID", "metric must be 1-120 characters")
    if len(notes) > MAX_NOTES:
        raise ProductMissionError("OUTCOME_NOTES_LIMIT", f"notes must be at most {MAX_NOTES} characters")
    if evidence_class == "measured" and not (source and source.strip()):
        raise ProductMissionError("MEASURED_SOURCE_REQUIRED", "measured outcomes require a source")
    for name, selected in (("VALUE", value), ("TARGET", target)):
        if selected is not None and (isinstance(selected, bool) or not isinstance(selected, (int, float)) or not math.isfinite(selected)):
            raise ProductMissionError(f"OUTCOME_{name}_INVALID", f"{name.lower()} must be numeric or null")


def _last_outcome_sha(path: Path) -> str | None:
    if not path.exists():
        return None
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return json.loads(lines[-1]).get("record_sha256") if lines else None


def _outcome_verdict(value: float | None, target: float | None) -> str:
    if value is None or target is None:
        return "inconclusive"
    return "achieved" if value >= target else "not_achieved"


def record_outcome(mission_path: Path, root: Path, metric: str, value: float | None, target: float | None,
                   evidence_class: str, source: str | None = None, notes: str = "") -> dict:
    """Append a hash-linked outcome while preserving evidence-quality boundaries."""
    verification = verify_mission(mission_path)
    if not verification["valid"]:
        raise ProductMissionError("MISSION_INPUT_DRIFT", "; ".join(verification["errors"]))
    _validate_outcome(metric, value, target, evidence_class, source, notes)
    mission = _load_json(mission_path, MISSION_SCHEMA)
    path = Path(root).resolve() / ".factory" / "outcomes" / f"{mission['id']}.jsonl"
    previous = _last_outcome_sha(path)
    verdict = _outcome_verdict(value, target)
    core = {
        "schema": OUTCOME_SCHEMA,
        "mission_id": mission["id"],
        "mission_sha256": mission["mission_sha256"],
        "metric": metric.strip(),
        "value": value,
        "target": target,
        "evidence_class": evidence_class,
        "source": source.strip() if source else None,
        "notes": notes,
        "verdict": verdict,
        "previous_sha256": previous,
        "recorded_at": _now(),
        "markers": ["OUTCOME_EVIDENCE_CLASSIFIED", "OUTCOME_CHAIN_BOUND"],
    }
    record = {**core, "record_sha256": _sha_bytes(_canonical(core))}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return {**record, "path": str(path)}


def outcome_summary(root: Path, mission_id: str | None = None) -> dict[str, Any]:
    """Summarize local outcome evidence without upgrading modeled data to measured."""
    directory = Path(root).resolve() / ".factory" / "outcomes"
    paths = [directory / f"{mission_id}.jsonl"] if mission_id else sorted(directory.glob("*.jsonl")) if directory.exists() else []
    records = []
    chain_errors = []
    for path in paths:
        previous = None
        if not path.exists():
            continue
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            core = {key: value for key, value in record.items() if key != "record_sha256"}
            if record.get("previous_sha256") != previous or record.get("record_sha256") != _sha_bytes(_canonical(core)):
                chain_errors.append(f"{path.name}:{line_number}")
            previous = record.get("record_sha256")
            records.append(record)
    classes = {name: sum(item.get("evidence_class") == name for item in records) for name in sorted(EVIDENCE_CLASSES)}
    return {
        "schema": "factory.outcome.summary.v1",
        "records": len(records),
        "evidence_classes": classes,
        "verdicts": {name: sum(item.get("verdict") == name for item in records) for name in ("achieved", "not_achieved", "inconclusive")},
        "chain_valid": not chain_errors,
        "chain_errors": chain_errors,
        "scope_limits": ["Outcome evidence is local and caller-supplied.", "Only measured records with a named source support measured product claims."],
    }
