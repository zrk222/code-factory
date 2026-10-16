"""Deterministic PRD-to-PR value compiler with governed mission handoffs."""

from __future__ import annotations

from . import canonical_json_compat_bytes as _canonical

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
import hashlib
import json
import math
import os
import re
import stat
import tempfile
import time

from .loop_passport import (
    DESTRUCTIVE_ACTIONS,
    build_loop_passport,
    default_manifest,
    verify_loop_passport,
)
from .failure_guidance import explain_failure
from .assembly_process import run_cli_detailed
from .migration import verify_migration_readiness, verify_repository_context
from .agent_contract import AgentContractError, validate_verifier_attestation


PRODUCT_GRAPH_SCHEMA = "factory.product_graph.v1"
VALUE_SLICES_SCHEMA = "factory.value_slices.v1"
MISSION_SCHEMA = "factory.mission.v1"
MISSION_CONTRACT_REVISION = 2
PR_DRAFT_SCHEMA = "factory.pr_draft.v1"
OUTCOME_SCHEMA = "factory.outcome.v1"
MISSION_COMPLETION_SCHEMA = "factory.mission.completion.v1"
MISSION_VALIDATION_INPUT_SCHEMA = "factory.mission.validation-input.v1"
DAILY_VERIFICATION_SCHEMA = "factory.mission.daily-verification.v1"
_DAILY_VERIFICATION_UNSET = object()
MISSION_DECISION_SCHEMA = "factory.mission.decision.v1"
CANDIDATE_BINDING_SCHEMA = "factory.mission.candidate-binding.v1"
TASK_PACKET_SCHEMA = "factory.small_agent_task_packet.v1"
MAX_PRD_BYTES = 65536
MAX_REQUIREMENTS = 500
MAX_SLICE_REQUIREMENTS = 5
MAX_NOTES = 4000
MAX_COMPLETION_CRITERIA = 200
MAX_COMPLETION_EVIDENCE = 100
MAX_DAILY_SOURCE_BYTES = 1_000_000
MAX_DAILY_TOTAL_SOURCE_BYTES = 16_000_000
MAX_DAILY_RECEIPT_BYTES = 1_000_000
EXECUTORS = frozenset({"manual", "codex", "copilot", "claude", "custom"})
EVIDENCE_CLASSES = frozenset({"measured", "observed", "modeled", "unknown"})
MISSION_DECISIONS = frozenset({"approved_execution", "deferred", "rejected"})
UX_STATES = (
    "loading",
    "empty",
    "error",
    "success",
    "recovery",
    "permission",
    "offline",
    "accessibility",
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
        raise ProductMissionError(
            "ARTIFACT_INVALID", f"cannot read JSON artifact {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise ProductMissionError(
            "ARTIFACT_INVALID", f"artifact must be a JSON object: {path}"
        )
    if schema and value.get("schema") != schema:
        raise ProductMissionError("SCHEMA_UNSUPPORTED", f"expected {schema}: {path}")
    return value


def _load_mission(path: Path) -> dict[str, Any]:
    """Load current missions and explicitly supported v1 legacy contracts."""
    mission = _load_json(path)
    revision = mission.get("contract_revision", 1)
    if (
        mission.get("schema") != MISSION_SCHEMA
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision not in {1, MISSION_CONTRACT_REVISION}
    ):
        raise ProductMissionError(
            "SCHEMA_UNSUPPORTED",
            f"expected {MISSION_SCHEMA} revision 1 or {MISSION_CONTRACT_REVISION}: {path}",
        )
    return mission


def _atomic_text(path: Path, text: str, *, force: bool = False) -> Path:
    path = Path(path)
    data = text.encode("utf-8")
    if path.exists():
        if path.read_bytes() == data:
            return path
        if not force:
            raise ProductMissionError(
                "ARTIFACT_EXISTS", f"refusing to replace {path}; use --force"
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
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
    return _atomic_text(
        path, json.dumps(value, indent=2, sort_keys=True) + "\n", force=force
    )


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
    explicit = re.match(
        r"^((?:REQ|FR|NFR)-[A-Za-z0-9_.-]+)\s*[:.-]?\s+", statement, re.I
    )
    if explicit:
        return explicit.group(1).upper()
    normalized = " ".join(statement.lower().split())
    return f"REQ-{_sha_bytes(normalized.encode('utf-8'))[:10].upper()}"


def _is_requirement(statement: str, section: str) -> bool:
    section_words = section.lower()
    if any(
        word in section_words
        for word in ("requirement", "feature", "user stor", "must")
    ):
        return True
    return bool(
        re.search(
            r"\b(?:shall|must|as an?\s+.+?\s+i want|when\s+.+?\s+then)\b",
            statement,
            re.I,
        )
    )


def _requirement_kind(statement: str, section: str) -> str:
    value = f"{section} {statement}".lower()
    if any(
        word in value
        for word in ("security", "privacy", "permission", "encrypt", "auth")
    ):
        return "trust"
    if any(
        word in value
        for word in ("latency", "performance", "availability", "reliability")
    ):
        return "nonfunctional"
    if any(
        word in value
        for word in (
            "screen",
            "page",
            "button",
            "form",
            "user",
            "operator",
            "customer",
            "dashboard",
            "login",
            "mobile",
            "web",
        )
    ):
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
            for item in re.findall(
                r"\b(?:REQ|FR|NFR)-[A-Za-z0-9_.-]+\b", normalized, re.I
            )
        }
        dependencies.discard(requirement_id)
        kind = _requirement_kind(normalized, section)
        requirements.append(
            {
                "id": requirement_id,
                "statement": normalized,
                "section": section,
                "source_line": number,
                "kind": kind,
                "user_facing": kind == "experience",
                "depends_on_requirements": sorted(dependencies),
            }
        )
    if len(requirements) > MAX_REQUIREMENTS:
        raise ProductMissionError(
            "REQUIREMENT_LIMIT",
            f"PRD contains more than {MAX_REQUIREMENTS} requirement atoms",
        )
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
        "desired_outcomes": _bullets_in_sections(
            text, ("desired outcome", "outcome", "goal")
        ),
        "journeys": _bullets_in_sections(text, ("journey", "workflow", "user flow")),
        "business_rules": _bullets_in_sections(
            text, ("business rule", "policy", "decision rule")
        ),
        "data_ownership": _bullets_in_sections(
            text, ("data ownership", "data owner", "retention", "export", "deletion")
        ),
        "trust_boundaries": _bullets_in_sections(
            text, ("trust boundary", "trust", "security boundary", "privacy boundary")
        ),
        "external_effects": _bullets_in_sections(
            text,
            (
                "external effect",
                "side effect",
                "message",
                "deploy",
                "publish",
                "payment",
            ),
        ),
        "approval_requirements": _bullets_in_sections(
            text, ("approval", "human review", "authorization")
        ),
        "success_events": _bullets_in_sections(
            text, ("success event", "outcome event", "metric event", "telemetry")
        ),
    }


def _extract_acceptance(text: str) -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^\s*Scenario(?: Outline)?:\s*(.+?)\s*$", line, re.I)
        if match:
            current = {
                "id": f"AC-{len(scenarios) + 1:03d}",
                "title": match.group(1),
                "source_line": number,
                "steps": [],
            }
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
            result[state] = (
                "declared"
                if re.search(rf"\b{re.escape(state)}\b", lowered)
                else "missing"
            )
    return result


def _graph_mermaid(graph: dict[str, Any]) -> str:
    lines = ["flowchart LR", '    P["PRD source"] --> G["Product Graph"]']
    for index, requirement in enumerate(graph["requirements"], 1):
        label = requirement["id"].replace('"', "'")
        lines.append(f'    G --> R{index}["{label}"]')
    lines.extend(
        [
            '    G --> X["Gap inventory"]',
            '    G --> U["UX state audit"]',
            '    G --> O["Outcome contract"]',
        ]
    )
    return "\n".join(lines) + "\n"


def _project_name(text: str, fallback: str) -> str:
    title = re.search(r"^#\s+(.+?)\s*$", text, re.M)
    return _slug(title.group(1) if title else fallback)


def _product_gaps(
    requirements: list[dict[str, Any]],
    acceptance: list[dict[str, Any]],
    actors: list[str],
    outcomes: list[str],
    ux_states: dict[str, str],
    facts: dict[str, list[str]],
) -> list[dict[str, str]]:
    gaps: list[dict[str, str]] = []
    checks = (
        (
            not requirements,
            "REQUIREMENTS_MISSING",
            "blocking",
            "Add at least one testable requirement.",
        ),
        (
            not acceptance,
            "ACCEPTANCE_MISSING",
            "blocking",
            "Add at least one Gherkin Scenario.",
        ),
        (not actors, "ACTORS_MISSING", "advisory", "Name the user or operator roles."),
        (
            not outcomes,
            "OUTCOMES_MISSING",
            "advisory",
            "Declare a measurable product outcome.",
        ),
        (
            not facts["journeys"],
            "JOURNEYS_MISSING",
            "advisory",
            "Declare at least one end-to-end user journey.",
        ),
        (
            not facts["data_ownership"],
            "DATA_OWNERSHIP_MISSING",
            "advisory",
            "Declare who owns, exports, retains, and deletes product data.",
        ),
        (
            not facts["trust_boundaries"],
            "TRUST_BOUNDARIES_MISSING",
            "advisory",
            "Declare the product trust boundaries.",
        ),
        (
            not facts["approval_requirements"],
            "APPROVAL_REQUIREMENTS_MISSING",
            "advisory",
            "Declare which external or irreversible effects require approval.",
        ),
        (
            not facts["success_events"],
            "SUCCESS_EVENTS_MISSING",
            "advisory",
            "Declare measurable events that prove the product outcome.",
        ),
    )
    gaps.extend(
        {"code": code, "severity": severity, "message": message}
        for missing, code, severity, message in checks
        if missing
    )
    gaps.extend(
        {
            "code": f"UX_{state.upper()}_MISSING",
            "severity": "advisory",
            "message": f"Declare the {state} experience state.",
        }
        for state, status in ux_states.items()
        if status == "missing"
    )
    return gaps


def analyze_product_text(
    text: str,
    source_name: str,
    project: str | None = None,
    bindings: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Return deterministic Product Graph facts without writing product artifacts."""
    source_bytes = text.encode("utf-8")
    if not source_bytes or len(source_bytes) > MAX_PRD_BYTES:
        raise ProductMissionError(
            "PRD_SIZE_INVALID", f"PRD must be 1-{MAX_PRD_BYTES} UTF-8 bytes"
        )
    project_id = (
        _slug(project) if project else _project_name(text, Path(source_name).stem)
    )
    requirements = _extract_requirements(text)
    acceptance = _extract_acceptance(text)
    actors = _extract_actors(text)
    facts = _extract_product_facts(text)
    outcomes = _bullets_in_sections(text, ("outcome", "success", "goal", "metric"))
    constraints = _bullets_in_sections(
        text, ("constraint", "non-functional", "guardrail", "security", "privacy")
    )
    assumptions = _bullets_in_sections(text, ("assumption",))
    unknowns = _bullets_in_sections(text, ("unknown", "question", "open issue"))
    ux_states = _ux_audit(text, requirements)
    gaps = _product_gaps(requirements, acceptance, actors, outcomes, ux_states, facts)
    source_sha = _sha_bytes(source_bytes)
    core = {
        "schema": PRODUCT_GRAPH_SCHEMA,
        "project": project_id,
        "source": {
            "name": Path(source_name).name,
            "sha256": source_sha,
            "bytes": len(source_bytes),
        },
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
        "status": "needs_input"
        if any(item["severity"] == "blocking" for item in gaps)
        else "ready",
        "markers": [
            "PRODUCT_GRAPH_BOUND",
            "REQUIREMENT_ATOMS_STABLE",
            "PRODUCT_GAPS_EXPOSED",
            "UX_STATES_AUDITED",
            "PRODUCT_TRUST_MODEL_BOUND",
            "PRODUCT_OUTCOME_EVENTS_BOUND",
        ],
    }
    return core


def compile_product_text(
    text: str,
    *,
    root: Path,
    source_name: str,
    project: str | None = None,
    force: bool = False,
    bindings: dict[str, str] | None = None,
    intake_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile UTF-8 PRD text into a local Product Graph and gap inventory."""
    core = analyze_product_text(
        text, source_name=source_name, project=project, bindings=bindings
    )
    if intake_binding is not None:
        core["intake"] = intake_binding
        core["markers"] = [*core["markers"], "PRODUCT_INTAKE_CONFIRMATION_BOUND"]
    project_id = core["project"]
    graph = {
        **core,
        "graph_sha256": _sha_bytes(_canonical(core)),
        "generated_at": _now(),
    }
    directory = Path(root).resolve() / ".factory" / "products" / project_id
    graph_path = directory / "product_graph.json"
    if graph_path.exists() and not force:
        existing = _load_json(graph_path, PRODUCT_GRAPH_SCHEMA)
        if existing.get("graph_sha256") == graph["graph_sha256"]:
            return {
                **existing,
                "path": str(graph_path),
                "mermaid": str(directory / "product_graph.mmd"),
                "idempotent": True,
            }
        raise ProductMissionError(
            "PRODUCT_GRAPH_EXISTS", f"product graph changed: {graph_path}; use --force"
        )
    _atomic_text(directory / "source.md", text, force=force)
    _atomic_json(graph_path, graph, force=force)
    _atomic_text(directory / "product_graph.mmd", _graph_mermaid(graph), force=force)
    return {
        **graph,
        "path": str(graph_path),
        "mermaid": str(directory / "product_graph.mmd"),
        "idempotent": False,
    }


def compile_product_prd(
    prd_path: Path,
    root: Path,
    project: str | None = None,
    force: bool = False,
    intake_path: Path | None = None,
) -> dict:
    """Compile one UTF-8 PRD file into a traceable Product Graph."""
    path = Path(prd_path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ProductMissionError("PRD_NOT_FOUND", f"cannot read PRD: {path}") from exc
    if len(data) > MAX_PRD_BYTES:
        raise ProductMissionError(
            "PRD_SIZE_INVALID", f"PRD must be at most {MAX_PRD_BYTES} UTF-8 bytes"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProductMissionError(
            "PRD_ENCODING_INVALID", "PRD must be valid UTF-8"
        ) from exc
    intake_binding: dict[str, Any] | None = None
    if intake_path is not None:
        # Keep the intake subsystem optional for legacy graphs, but fail closed
        # whenever a caller explicitly asks to bind an intake confirmation.
        from .intake_grill import verify_intake_confirmation

        workspace = Path(root).resolve()
        confirmation_path = Path(intake_path)
        confirmation_path = (
            confirmation_path.resolve()
            if confirmation_path.is_absolute()
            else (workspace / confirmation_path).resolve()
        )
        confirmation = verify_intake_confirmation(workspace, confirmation_path)
        if not confirmation["valid"] or not isinstance(
            confirmation.get("confirmation"), dict
        ):
            raise ProductMissionError(
                "INTAKE_CONFIRMATION_INVALID",
                "; ".join(confirmation["errors"]) or "intake confirmation is invalid",
            )
        value = confirmation["confirmation"]
        source_sha = _sha_bytes(data)
        if value.get("source", {}).get("sha256") != source_sha:
            raise ProductMissionError(
                "INTAKE_SOURCE_MISMATCH",
                "intake confirmation is bound to different PRD bytes",
            )
        decision = value["decision"]
        intake_binding = {
            "path": str(confirmation_path),
            "file_sha256": _sha_path(confirmation_path),
            "confirmation_sha256": value["confirmation_sha256"],
            "source_sha256": source_sha,
            "framework": decision["framework"],
            "intent_sha256": _sha_bytes(decision["intent"].encode("utf-8")),
            "acceptance_sha256": _sha_bytes(decision["acceptance"].encode("utf-8")),
            "external_effects": decision["external_effects"],
        }
    return compile_product_text(
        text,
        root=root,
        source_name=str(path),
        project=project,
        force=force,
        intake_binding=intake_binding,
    )


def verify_product_graph(graph_path: Path) -> dict[str, Any]:
    """Verify a Product Graph's own hash and its captured PRD source binding."""
    graph = _load_json(graph_path, PRODUCT_GRAPH_SCHEMA)
    core = {
        key: value
        for key, value in graph.items()
        if key not in {"graph_sha256", "generated_at"}
    }
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
    if any(
        word in text for word in ("auth", "permission", "security", "privacy", "secret")
    ):
        gates.append("security")
    if any(
        word in text for word in ("api", "webhook", "connector", "external", "sync")
    ):
        gates.append("integration")
    return gates


def _slice_risk(requirements: list[dict[str, Any]]) -> str:
    gates = _slice_gates(requirements)
    if "security" in gates or "integration" in gates:
        return "high"
    if "accessibility" in gates or len(requirements) > 3:
        return "medium"
    return "low"


def _slice_score(
    requirements: list[dict[str, Any]], graph: dict[str, Any]
) -> dict[str, int]:
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
        "user_value": min(
            5,
            1
            + sum(item["user_facing"] for item in requirements)
            + bool(graph.get("outcomes")),
        ),
        "uncertainty_retired": min(
            5, 1 + len(graph.get("unknowns", [])) + len(graph.get("assumptions", []))
        ),
        "dependency_unlock": min(5, dependent_count),
        "security_change_risk": risk,
        "implementation_review_cost": min(
            5, len(requirements) + max(0, len(gates) - 3) // 2
        ),
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


def _requirement_groups(
    requirements: list[dict[str, Any]], maximum: int
) -> list[tuple[str, list[dict[str, Any]]]]:
    groups: list[tuple[str, list[dict[str, Any]]]] = []
    for requirement in requirements:
        name = _theme(requirement)
        if not groups or groups[-1][0] != name or len(groups[-1][1]) >= maximum:
            groups.append((name, []))
        groups[-1][1].append(requirement)
    return groups


def _value_slice(
    name: str, requirements: list[dict[str, Any]], graph: dict[str, Any]
) -> dict[str, Any]:
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
            "ui": "implement declared UX states"
            if any(item["user_facing"] for item in requirements)
            else "not_applicable",
            "behavior": "implement every bound requirement",
            "api_data": "preserve declared data ownership and trust boundaries",
            "tests": ["unit", "acceptance", "requirement-mutation"],
            "observability": ["slice_started", "slice_completed", "slice_failed"],
            "rollback": "revert the slice commit and invalidate receipts derived from it",
        },
        "experience_contract": {
            "required_states": [
                state
                for state, status in graph["ux_states"].items()
                if status != "not_applicable"
            ],
            "missing_states": [
                state
                for state, status in graph["ux_states"].items()
                if status == "missing"
            ],
        },
        "acceptance_refs": [item["id"] for item in graph["acceptance"]],
        "depends_on": [],
    }


def _bind_slice_dependencies(
    slices: list[dict[str, Any]], requirements: list[dict[str, Any]]
) -> None:
    owners = {
        requirement_id: item["id"]
        for item in slices
        for requirement_id in item["requirement_ids"]
    }
    requirements_by_id = {item["id"]: item for item in requirements}
    for item in slices:
        dependencies = {
            owners[dependency]
            for requirement_id in item["requirement_ids"]
            for dependency in requirements_by_id[requirement_id][
                "depends_on_requirements"
            ]
            if dependency in owners and owners[dependency] != item["id"]
        }
        item["depends_on"] = sorted(dependencies)


def _validate_slice_coverage(
    slices: list[dict[str, Any]], requirements: list[dict[str, Any]]
) -> tuple[list[str], list[str]]:
    assigned = [
        requirement for item in slices for requirement in item["requirement_ids"]
    ]
    expected = [item["id"] for item in requirements]
    if len(assigned) != len(set(assigned)) or sorted(assigned) != sorted(expected):
        raise ProductMissionError(
            "SLICE_COVERAGE_INVALID", "every requirement must be assigned exactly once"
        )
    return assigned, expected


def plan_value_slices(
    graph_path: Path, root: Path, max_requirements: int = 3, force: bool = False
) -> dict:
    """Assign every requirement exactly once to a deterministic vertical slice."""
    if max_requirements < 1 or max_requirements > MAX_SLICE_REQUIREMENTS:
        raise ProductMissionError(
            "SLICE_BOUND_INVALID",
            f"max requirements must be 1-{MAX_SLICE_REQUIREMENTS}",
        )
    graph = _load_json(graph_path, PRODUCT_GRAPH_SCHEMA)
    blocking = [
        item for item in graph.get("gaps", []) if item.get("severity") == "blocking"
    ]
    if blocking:
        raise ProductMissionError(
            "MISSION_BLOCKED_BY_PRODUCT_GAPS",
            ", ".join(item["code"] for item in blocking),
        )
    slices = [
        _value_slice(name, requirements, graph)
        for name, requirements in _requirement_groups(
            graph["requirements"], max_requirements
        )
    ]
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
            "requirements": len(expected),
            "assigned": len(assigned),
            "deferred": [],
            "rejected": [],
            "unresolved": [],
            "complete": True,
        },
        "status": "ready",
        "markers": [
            "VALUE_SLICES_COVERAGE_COMPLETE",
            "DEPENDENCY_ORDER_DETERMINISTIC",
            "VALUE_SLICE_SCORE_DETERMINISTIC",
            "VERTICAL_SLICE_CONTRACT_BOUND",
        ],
    }
    plan = {
        **core,
        "slices_sha256": _sha_bytes(_canonical(core)),
        "generated_at": _now(),
    }
    directory = Path(root).resolve() / ".factory" / "products" / graph["project"]
    path = directory / "value_slices.json"
    if path.exists() and not force:
        existing = _load_json(path, VALUE_SLICES_SCHEMA)
        if existing.get("slices_sha256") == plan["slices_sha256"]:
            return {
                **existing,
                "path": str(path),
                "mermaid": str(directory / "value_slices.mmd"),
                "idempotent": True,
            }
        raise ProductMissionError(
            "VALUE_SLICES_EXISTS", f"slice plan changed: {path}; use --force"
        )
    _atomic_json(path, plan, force=force)
    _atomic_text(directory / "value_slices.mmd", _slices_mermaid(plan), force=force)
    return {
        **plan,
        "path": str(path),
        "mermaid": str(directory / "value_slices.mmd"),
        "idempotent": False,
    }


def _bounded_budget(name: str, value: float | int | None) -> float | int:
    maximum = MISSION_MAXIMA[name]
    selected = maximum if value is None else value
    if (
        isinstance(selected, bool)
        or not isinstance(selected, (int, float))
        or selected < 0
        or selected > maximum
    ):
        raise ProductMissionError(
            "MISSION_BUDGET_INVALID", f"{name} must be between 0 and {maximum}"
        )
    if name in {"max_iterations", "max_wall_seconds"} and selected < 1:
        raise ProductMissionError(
            "MISSION_BUDGET_INVALID", f"{name} must be at least 1"
        )
    return selected


def _completion_criteria(selected: dict[str, Any]) -> list[dict[str, Any]]:
    criteria = [
        {
            "id": f"requirement:{item}",
            "kind": "requirement",
            "description": f"Prove {item}.",
            "verification_kind": "deterministic_test",
            "evidence_contract": {"local_hash_bound": True},
        }
        for item in selected["requirement_ids"]
    ]
    criteria.extend(
        {
            "id": f"acceptance:{item}",
            "kind": "acceptance",
            "description": f"Pass {item}.",
            "verification_kind": "deterministic_test",
            "evidence_contract": {"local_hash_bound": True},
        }
        for item in selected["acceptance_refs"]
    )
    criteria.extend(
        {
            "id": f"gate:{_slug(item)}",
            "kind": "gate",
            "description": f"Pass the {item} gate.",
            "verification_kind": "deterministic_tool",
            "evidence_contract": {"local_hash_bound": True},
        }
        for item in selected["gates"]
    )
    if selected["vertical_contract"]["ui"] != "not_applicable":
        criteria.append(
            {
                "id": f"browser-flow:{selected['id']}",
                "kind": "browser_control",
                "description": f"Complete the primary user outcome for {selected['id']} in fewer than four interactions.",
                "verification_kind": "browser_control",
                "evidence_contract": {
                    "schema": "factory.browser-flow.evidence.v1",
                    "max_clicks": 3,
                    "exact_url_match": True,
                    "all_assertions_required": True,
                    "screenshot_hashes_required": True,
                },
            }
        )
    if not criteria or len(criteria) > MAX_COMPLETION_CRITERIA:
        raise ProductMissionError(
            "NO_FINISH_CONTRACT",
            f"mission must define 1-{MAX_COMPLETION_CRITERIA} criteria",
        )
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
            "allowed": [
                "MISSION.md",
                "candidate_diff",
                "evidence_manifest",
                "hash_bound_attempt_summary",
            ],
            "forbidden": [
                "creator_hidden_reasoning",
                "creator_transcript",
                "failed_attempt_history",
            ],
        },
    }


def _mission_context(mission: dict[str, Any], selected: dict[str, Any]) -> str:
    packet = mission["task_packet"]
    requirements = "\n".join(
        f"- {item['id']}: {item['statement']}" for item in packet["requirements"]
    )
    acceptance = (
        "\n".join(
            f"- {item['id']}: {item['title']}\n"
            + "\n".join(f"  {step}" for step in item["steps"])
            for item in packet["acceptance_examples"]
        )
        or "- No acceptance scenario was bound. Stop and request owner review."
    )
    dependencies = (
        "\n".join(f"- {item}" for item in packet["dependencies"]) or "- None declared."
    )
    gates = "\n".join(f"- {item}" for item in selected["gates"])
    budgets = "\n".join(
        f"- {name}: {value}" for name, value in packet["budgets"].items()
    )
    lanes = "\n".join(
        f"- {item['lane']}: {item['applicability']} — {item['reason']}"
        for item in packet["audit_lanes"]
    )
    return f"""# Mission: {mission["id"]}

Status: prepared only. Candidate scope is unresolved; this packet does not signal readiness.

## User outcome

{selected["user_outcome"]}

## Bound requirements

{requirements}

## Acceptance examples

{acceptance}

## Dependencies

{dependencies}

## Required gates

{gates}

## Budgets

{budgets}

## Audit lane applicability

{lanes}

## Bound inputs

- Product Graph: `{mission["inputs"]["graph_sha256"]}`
- Value slices: `{mission["inputs"]["slices_sha256"]}`
- Loop Passport: `{mission["loop"]["passport_sha256"]}`
- Task packet: `{packet["packet_sha256"]}`

## Preparation and stop condition

Preparation only: candidate files, interfaces, and commands are not bound, and
no audit has run. Stop before edits until the owner declares the candidate
paths and interfaces, binds their hashes, and records the required human
execution decision. Stop if any bound source changes or the declared scope
does not contain the requested work.

## Workspace and roles

- Proposed worktree: `{mission["workspace_contract"]["path"]}`
- Branch: `{mission["workspace_contract"]["branch"]}`
- Builder may write only within the candidate paths after scope binding and approval.
- Checker receives the candidate diff and evidence, not creator-private reasoning.
- UX reviewer may attach browser evidence but may not modify or promote the candidate.

This packet does not grant merge, publish, deploy, external-message, credential,
connector, or production-write authority.
"""


def _small_agent_task_packet(
    mission_id: str,
    graph_path: Path,
    graph: dict[str, Any],
    slices_path: Path,
    slices: dict[str, Any],
    selected: dict[str, Any],
    budget: dict[str, Any],
) -> dict[str, Any]:
    """Prepare a bound task brief; candidate scope and execution remain unresolved."""
    requirement_ids = set(selected["requirement_ids"])
    requirements = [
        {
            key: item[key]
            for key in ("id", "statement", "kind", "depends_on_requirements")
            if key in item
        }
        for item in graph["requirements"]
        if item["id"] in requirement_ids
    ]
    acceptance = [
        item
        for item in graph["acceptance"]
        if item["id"] in selected["acceptance_refs"]
    ]
    lanes = ["static", "secrets", "configuration", "dependencies", "runtime", "fuzz"]
    core = {
        "schema": TASK_PACKET_SCHEMA,
        "mission_id": mission_id,
        "status": "prepared_needs_candidate_binding",
        "actor": graph["actors"] or ["UNKNOWN: PRD does not declare an actor"],
        "user_visible_outcome": {
            "slice": selected["user_outcome"],
            "declared_product_outcomes": graph["outcomes"],
        },
        "requirements": requirements,
        "acceptance_examples": acceptance,
        "counterexamples": {
            "status": "not_declared",
            "source": "Product Graph contains no counterexample contract",
        },
        "source_bindings": {
            "product_graph": {
                "path": str(graph_path.resolve()),
                "file_sha256": _sha_path(graph_path),
                "content_sha256": graph["graph_sha256"],
            },
            "value_slices": {
                "path": str(slices_path.resolve()),
                "file_sha256": _sha_path(slices_path),
                "content_sha256": slices["slices_sha256"],
            },
        },
        "interfaces": {
            "declared_bindings": dict(graph.get("bindings", {})),
            "relevant_files": {
                "status": "unknown_until_candidate_inspection",
                "paths": [],
            },
            "contracts": {"status": "unknown_unless_declared_in_bindings"},
        },
        "dependencies": selected["depends_on"],
        "permitted_source_scope": {
            "status": "requires_human_candidate_declaration",
            "paths": [],
            "scope_drift": "stop_and_request_owner_review",
        },
        "acceptance_commands": {
            "status": "requires_declared_tool_manifest_and_candidate_scope",
            "commands": [],
        },
        "budgets": dict(budget),
        "stop_rules": [
            "Stop before edits until candidate paths and interfaces are declared and bound.",
            "Stop if a declared source hash, requirement, acceptance reference, or permitted path changes.",
            "Stop at any budget limit, missing tool, missing control, failed gate, or unresolved external effect.",
            "Do not weaken tests, acceptance oracles, policy, or required gates to obtain a pass.",
            "Request owner review for scope expansion or an unmet requirement; do not infer authority.",
        ],
        "audit_lanes": [
            {
                "lane": lane,
                "applicability": "requires_candidate_declaration",
                "reason": "Candidate files and runtime profile are not yet bound.",
            }
            for lane in lanes
        ],
        "regression_controls": {
            "positive": {
                "required": True,
                "status": "not_run",
                "definition": "Declare an independent expected-behavior oracle.",
            },
            "negative": {
                "required": True,
                "status": "not_run",
                "definition": "Declare a scope-drift or gate-weakening sabotage that must be rejected.",
            },
            "preserve_existing_gates": True,
        },
        "execution": {
            "state": "preparation_only",
            "candidate_sha256": None,
            "requires_candidate_binding": True,
            "requires_human_execution_decision": True,
            "executed_audit": False,
            "release_authority": False,
        },
    }
    return {**core, "packet_sha256": _sha_bytes(_canonical(core))}


def _verify_task_packet_sources(
    packet: dict[str, Any], mission: dict[str, Any]
) -> list[str]:
    inputs = mission.get("inputs", {})
    bindings = packet.get("source_bindings")
    if not isinstance(inputs, dict) or not isinstance(bindings, dict):
        return ["small-agent task packet source bindings malformed"]
    for name, key in (("product_graph", "graph"), ("value_slices", "slices")):
        binding = bindings.get(name)
        if not isinstance(binding, dict) or any(
            binding.get(field) != inputs.get(input_key)
            for field, input_key in (
                ("path", f"{key}_path"),
                ("file_sha256", f"{key}_file_sha256"),
                ("content_sha256", f"{key}_sha256"),
            )
        ):
            return [f"small-agent task packet {name} binding invalid"]
    selected = mission.get("slice", {})
    if [
        item.get("id")
        for item in packet.get("requirements", [])
        if isinstance(item, dict)
    ] != selected.get("requirement_ids"):
        return ["small-agent task packet requirements do not match the selected slice"]
    if [
        item.get("id")
        for item in packet.get("acceptance_examples", [])
        if isinstance(item, dict)
    ] != selected.get("acceptance_refs"):
        return [
            "small-agent task packet acceptance references do not match the selected slice"
        ]
    if packet.get("dependencies") != selected.get("depends_on") or packet.get(
        "budgets"
    ) != mission.get("budgets"):
        return ["small-agent task packet dependencies or budgets invalid"]
    try:
        graph = _load_json(Path(inputs["graph_path"]), PRODUCT_GRAPH_SCHEMA)
    except (KeyError, ProductMissionError):
        return ["small-agent task packet graph source unavailable"]
    requirement_ids = set(selected.get("requirement_ids", []))
    expected_requirements = [
        {
            key: item[key]
            for key in ("id", "statement", "kind", "depends_on_requirements")
            if key in item
        }
        for item in graph.get("requirements", [])
        if item.get("id") in requirement_ids
    ]
    expected_acceptance = [
        item
        for item in graph.get("acceptance", [])
        if item.get("id") in selected.get("acceptance_refs", [])
    ]
    if (
        packet.get("requirements") != expected_requirements
        or packet.get("acceptance_examples") != expected_acceptance
    ):
        return ["small-agent task packet requirement or acceptance content drift"]
    interfaces = packet.get("interfaces")
    if not isinstance(interfaces, dict) or interfaces.get(
        "declared_bindings"
    ) != graph.get("bindings", {}):
        return ["small-agent task packet interface bindings invalid"]
    return []


def _verify_task_packet_controls(packet: dict[str, Any]) -> list[str]:
    execution = packet.get("execution", {})
    if not isinstance(execution, dict):
        return ["small-agent task packet execution authority malformed"]
    if (
        execution.get("state") != "preparation_only"
        or execution.get("candidate_sha256") is not None
        or execution.get("executed_audit") is not False
        or execution.get("release_authority") is not False
    ):
        return ["small-agent task packet execution authority invalid"]
    lanes = packet.get("audit_lanes")
    expected_lanes = {
        "static",
        "secrets",
        "configuration",
        "dependencies",
        "runtime",
        "fuzz",
    }
    if (
        not isinstance(lanes, list)
        or len(lanes) != len(expected_lanes)
        or any(not isinstance(item, dict) for item in lanes)
        or {item.get("lane") for item in lanes} != expected_lanes
        or any(
            item.get("applicability") != "requires_candidate_declaration"
            or not item.get("reason")
            for item in lanes
        )
    ):
        return ["small-agent task packet audit lane declarations invalid"]
    controls = packet.get("regression_controls", {})
    for name in ("positive", "negative"):
        control = controls.get(name) if isinstance(controls, dict) else None
        if (
            not isinstance(control, dict)
            or control.get("required") is not True
            or control.get("status") != "not_run"
            or not control.get("definition")
        ):
            return ["small-agent task packet regression controls invalid"]
    if controls.get("preserve_existing_gates") is not True:
        return ["small-agent task packet may not weaken existing gates"]
    return []


def _verify_small_agent_task_packet(mission: dict[str, Any]) -> list[str]:
    packet = mission.get("task_packet")
    if not isinstance(packet, dict):
        return ["small-agent task packet missing"]
    core = {key: value for key, value in packet.items() if key != "packet_sha256"}
    if packet.get("schema") != TASK_PACKET_SCHEMA or _sha_bytes(
        _canonical(core)
    ) != packet.get("packet_sha256"):
        return ["small-agent task packet schema or hash invalid"]
    if (
        packet.get("mission_id") != mission.get("id")
        or packet.get("status") != "prepared_needs_candidate_binding"
    ):
        return ["small-agent task packet identity or preparation state invalid"]
    source_errors = _verify_task_packet_sources(packet, mission)
    return source_errors or _verify_task_packet_controls(packet)


def _validated_slices(path: Path) -> dict[str, Any]:
    slices = _load_json(path, VALUE_SLICES_SCHEMA)
    core = {
        key: value
        for key, value in slices.items()
        if key not in {"slices_sha256", "generated_at"}
    }
    if _sha_bytes(_canonical(core)) != slices.get("slices_sha256"):
        raise ProductMissionError(
            "MISSION_INPUT_DRIFT", "Value slice content hash is invalid"
        )
    return slices


def _validated_graph(slices: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    graph_path = Path(slices["graph_path"])
    graph = _load_json(graph_path, PRODUCT_GRAPH_SCHEMA)
    core = {
        key: value
        for key, value in graph.items()
        if key not in {"graph_sha256", "generated_at"}
    }
    if _sha_bytes(_canonical(core)) != graph["graph_sha256"]:
        raise ProductMissionError(
            "MISSION_INPUT_DRIFT", "Product Graph content hash is invalid"
        )
    if slices.get("graph_sha256") != graph.get("graph_sha256"):
        raise ProductMissionError(
            "MISSION_INPUT_DRIFT",
            "Value slices were compiled from a different Product Graph",
        )
    return graph_path, graph


def _selected_slice(slices: dict[str, Any], slice_id: str) -> dict[str, Any]:
    selected = next((item for item in slices["slices"] if item["id"] == slice_id), None)
    if selected is None:
        raise ProductMissionError("SLICE_NOT_FOUND", f"slice not found: {slice_id}")
    return selected


def _existing_mission(path: Path, force: bool) -> dict[str, Any] | None:
    if not path.exists() or force:
        return None
    existing = _load_mission(path)
    verification = verify_mission(path)
    if verification["valid"]:
        return {**existing, "path": str(path), "idempotent": True}
    raise ProductMissionError(
        "MISSION_EXISTS", f"mission exists but is invalid: {path}; use --force"
    )


def _optional_mission_inputs(
    root: Path, readiness_path: Path | None, graph: dict[str, Any], require_intake: bool
) -> tuple[dict[str, Any], list[str]]:
    inputs: dict[str, Any] = {}
    markers: list[str] = []
    if readiness_path is not None:
        readiness = verify_migration_readiness(Path(readiness_path))
        if not readiness["valid"] or not readiness["ready"]:
            raise ProductMissionError(
                "MIGRATION_AGENT_NOT_READY",
                "; ".join(readiness["errors"])
                or "every readiness category requires executable proof",
            )
        inputs["migration_readiness"] = {
            "path": str(Path(readiness_path).resolve()),
            "sha256": _sha_path(Path(readiness_path)),
        }
        markers.append("MIGRATION_AGENT_READY_BOUND")
    context = root.resolve() / ".factory" / "context" / "context-receipt.json"
    if context.is_file() and verify_repository_context(context)["valid"]:
        inputs["repository_context"] = {
            "path": str(context),
            "sha256": _sha_path(context),
        }
        markers.append("REPOSITORY_CONTEXT_BOUND")
    intake_binding = _intake_confirmation_binding(root, graph, require_intake)
    if intake_binding is not None:
        inputs["intake_confirmation"] = intake_binding
        markers.append("INTAKE_CONFIRMATION_BOUND")
    return inputs, markers


def _intake_confirmation_binding(
    root: Path, graph: dict[str, Any], require_intake: bool
) -> dict[str, str] | None:
    intake = graph.get("intake")
    if intake is None:
        if require_intake:
            raise ProductMissionError(
                "INTAKE_CONFIRMATION_REQUIRED",
                "compile the Product Graph with a verified intake confirmation before creating this mission",
            )
        return None
    value = _verified_intake_confirmation(root, intake)
    _validate_intake_confirmation_hashes(graph, intake, value)
    return {
        "path": intake["path"],
        "sha256": intake["file_sha256"],
    }


def _verified_intake_confirmation(root: Path, intake: Any) -> dict[str, Any]:
    if not isinstance(intake, dict) or set(intake) != {
        "path",
        "file_sha256",
        "confirmation_sha256",
        "source_sha256",
        "framework",
        "intent_sha256",
        "acceptance_sha256",
        "external_effects",
    }:
        raise ProductMissionError(
            "INTAKE_CONFIRMATION_INVALID", "Product Graph intake binding is malformed"
        )
    from .intake_grill import verify_intake_confirmation

    confirmation = verify_intake_confirmation(root, Path(intake["path"]))
    if not confirmation["valid"] or not isinstance(
        confirmation.get("confirmation"), dict
    ):
        raise ProductMissionError(
            "INTAKE_CONFIRMATION_INVALID",
            "; ".join(confirmation["errors"]) or "intake confirmation is invalid",
        )
    return confirmation["confirmation"]


def _validate_intake_confirmation_hashes(
    graph: dict[str, Any], intake: dict[str, Any], value: dict[str, Any]
) -> None:
    if (
        _sha_path(Path(intake["path"])) != intake["file_sha256"]
        or value.get("confirmation_sha256") != intake["confirmation_sha256"]
    ):
        raise ProductMissionError(
            "INTAKE_CONFIRMATION_DRIFT", "intake confirmation file or hash changed"
        )
    if value.get("source", {}).get("sha256") != graph.get("source", {}).get(
        "sha256"
    ) or intake["source_sha256"] != graph.get("source", {}).get("sha256"):
        raise ProductMissionError(
            "INTAKE_SOURCE_MISMATCH",
            "Product Graph and intake confirmation are bound to different PRD bytes",
        )


def _mission_markers(criteria: list[dict[str, Any]], extra: list[str]) -> list[str]:
    markers = [
        "MISSION_PASSPORT_BOUND",
        "MISSION_BUDGET_HARD",
        "EXTERNAL_EFFECTS_APPROVAL_REQUIRED",
        "CREATOR_VERIFIER_CONTEXT_WALL",
        "NO_FINISH_CONTRACT",
        "MISSION_SINGLE_WORKTREE_BOUND",
        "MISSION_ROLE_PERMISSIONS_SEPARATE",
        "MISSION_CONTEXT_MINIMIZED",
        "MISSION_HYPOTHESES_BOUND",
        "MISSION_FRESH_CONTEXT_ATTEMPTS",
        "MISSION_MODEL_ROUTING_BOUNDED",
    ]
    if any(item["verification_kind"] == "browser_control" for item in criteria):
        markers.append("BROWSER_CONTROL_CRITERION_BOUND")
    return markers + extra


def create_mission(
    slices_path: Path,
    slice_id: str,
    root: Path,
    owner: str,
    executor: str = "manual",
    force: bool = False,
    max_iterations: int | None = None,
    max_wall_seconds: int | None = None,
    max_tokens: int | None = None,
    max_cost_usd: float | None = None,
    readiness_path: Path | None = None,
    require_intake: bool = False,
) -> dict:
    """Bind one approved slice into a supervised, budgeted mission contract."""
    if executor not in EXECUTORS:
        raise ProductMissionError(
            "EXECUTOR_UNSUPPORTED",
            f"executor must be one of {', '.join(sorted(EXECUTORS))}",
        )
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
    loop_manifest.update(
        {
            "autonomy": "supervised",
            "workspace": {
                "mode": "isolated",
                "allowed_paths": ["."],
                "network": "deny",
            },
            "capabilities": {
                "skills": [f"executor:{executor}"],
                "connectors": [],
                "actions": ["read_repository", "write_workspace", "execute_tests"],
            },
            "budgets": budget,
            "validators": {
                "pre": ["product_graph_complete", "slice_coverage_complete"],
                "post": ["tests", "requirement_coverage", "receipt_trace"],
                "invariant": ["no_unapproved_promotion", "hash_bound_sources"],
            },
            "approvals": {
                "required_for": sorted(
                    DESTRUCTIVE_ACTIONS
                    | {"external_message", "credential", "connector_grant"}
                ),
                "distinct_approver": True,
                "expires_minutes": 60,
            },
        }
    )
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
    optional_inputs, optional_markers = _optional_mission_inputs(
        Path(root), readiness_path, graph, require_intake
    )
    inputs.update(optional_inputs)
    task_packet = _small_agent_task_packet(
        mission_id,
        graph_path,
        graph,
        Path(slices_path),
        slices,
        selected,
        budget,
    )
    markers = _mission_markers(criteria, optional_markers)
    core = {
        "schema": MISSION_SCHEMA,
        "contract_revision": MISSION_CONTRACT_REVISION,
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
            "excluded_context": [
                "unrelated_prd_sections",
                "creator_private_reasoning",
                "unrelated_repository_history",
            ],
        },
        "task_packet": task_packet,
        "loop": loop,
        "budgets": budget,
        "role_permissions": {
            "builder": {
                "can": ["read_context_packet", "write_workspace", "run_approved_tools"],
                "cannot": [
                    "approve_own_work",
                    "merge",
                    "deploy",
                    "publish",
                    "external_message",
                ],
            },
            "checker": {
                "can": ["read_candidate_diff", "run_validators", "attach_evidence"],
                "cannot": [
                    "read_creator_private_reasoning",
                    "modify_candidate",
                    "merge",
                    "deploy",
                    "publish",
                ],
            },
            "ux_reviewer": {
                "can": [
                    "read_declared_ux_states",
                    "run_browser_checks",
                    "attach_screenshots",
                ],
                "cannot": ["modify_candidate", "approve_release", "deploy", "publish"],
            },
        },
        "orchestration": {
            "pattern": "creator_verifier",
            "creator": {
                "executor": executor,
                "reasoning_profile": "balanced_generation",
                "inputs": ["MISSION.md", "repository", "approved_tools"],
            },
            "verifier": {
                "executor": "independent",
                "reasoning_profile": "independent_high_reasoning",
                "inputs": ["mission.json", "candidate_diff", "evidence_manifest"],
            },
            "context_wall": {
                "required": True,
                "verifier_forbidden_inputs": [
                    "creator_scratchpad",
                    "creator_transcript",
                    "creator_hidden_reasoning",
                    "failed_attempt_history",
                ],
                "same_identity_allowed": False,
            },
            "attempt_policy": {
                "fresh_session_required": True,
                "max_attempts": budget["max_iterations"],
                "prior_attempt_context_allowed": False,
                "attempt_summary": "hash_bound_outcomes_only",
                "runtime_enforcement": "external_adapter_must_attest",
                "adapter_attestation_required": True,
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
        "authority": {
            "execute": "human_approval",
            "merge": False,
            "publish": False,
            "deploy": False,
            "external_message": False,
        },
        "markers": markers,
    }
    mission = {
        **core,
        "mission_sha256": _sha_bytes(_canonical(core)),
        "generated_at": _now(),
    }
    _atomic_json(mission_path, mission, force=force)
    context_path = directory / "MISSION.md"
    _atomic_text(context_path, _mission_context(mission, selected), force=force)
    return {
        **mission,
        "path": str(mission_path),
        "context": str(context_path),
        "idempotent": False,
    }


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
        return (
            []
            if check["valid"] and check["ready"]
            else ["migration readiness is no longer verified and ready"]
        )
    if name == "intake_confirmation":
        from .intake_grill import verify_intake_confirmation

        graph_path = Path(mission["inputs"]["graph_path"]).resolve()
        workspace = graph_path.parents[3]
        check = verify_intake_confirmation(workspace, path)
        return [] if check["valid"] else ["intake confirmation is no longer verified"]
    return (
        []
        if verify_repository_context(path)["valid"]
        else ["repository context is no longer verified"]
    )


def _verify_mission_passport(mission: dict[str, Any]) -> list[str]:
    path = Path(mission["loop"]["passport_path"])
    if not path.exists():
        return ["missing Loop Passport"]
    result = verify_loop_passport(path)
    if (
        not result["valid"]
        or result["passport_sha256"] != mission["loop"]["passport_sha256"]
    ):
        return ["Loop Passport invalid or changed"]
    return []


def _mission_hash_errors(mission: dict[str, Any]) -> list[str]:
    core = {
        key: value
        for key, value in mission.items()
        if key
        not in {"mission_sha256", "generated_at", "path", "context", "idempotent"}
    }
    return (
        []
        if _sha_bytes(_canonical(core)) == mission.get("mission_sha256")
        else ["mission hash mismatch"]
    )


def _mission_source_errors(mission: dict[str, Any]) -> list[str]:
    errors = []
    for name in ("graph", "slices"):
        errors.extend(_verify_primary_input(mission, name))
    for name in ("migration_readiness", "repository_context", "intake_confirmation"):
        errors.extend(_verify_optional_input(mission, name))
    errors.extend(_verify_mission_passport(mission))
    return errors


def _mission_packet_verification(
    mission: dict[str, Any],
) -> tuple[list[str], str]:
    has_packet = "task_packet" in mission
    revision = mission.get("contract_revision", 1)
    errors = []
    if revision == MISSION_CONTRACT_REVISION or has_packet:
        errors.extend(_verify_small_agent_task_packet(mission))
    if has_packet and not errors:
        status = "verified"
    elif revision == 1 and not has_packet:
        status = "legacy_unavailable"
    else:
        status = "invalid"
    return errors, status


def verify_mission(mission_path: Path) -> dict:
    """Verify mission identity, source artifacts, and Loop Passport without execution."""
    mission = _load_mission(mission_path)
    packet_errors, packet_status = _mission_packet_verification(mission)
    errors = _mission_hash_errors(mission)
    errors.extend(packet_errors)
    errors.extend(_mission_source_errors(mission))
    revision = mission.get("contract_revision", 1)
    return {
        "schema": "factory.mission.verification.v1",
        "mission_id": mission.get("id"),
        "valid": not errors,
        "status": "verified" if not errors else "invalid",
        "marker": "MISSION_VERIFIED" if not errors else "MISSION_INPUT_DRIFT",
        "errors": errors,
        "contract_version": f"{mission.get('schema')}/revision-{revision}",
        "task_packet_status": packet_status,
        "authority": "verification only; no execution or promotion authority",
    }


def decide_mission(
    mission_path: Path,
    root: Path,
    *,
    owner: str,
    decision: str,
    rationale: str,
    force: bool = False,
) -> dict[str, Any]:
    """Record one owner decision without granting downstream release authority."""
    verification = verify_mission(mission_path)
    if not verification["valid"]:
        raise ProductMissionError(
            "MISSION_INPUT_DRIFT", "; ".join(verification["errors"])
        )
    mission = _load_mission(mission_path)
    if owner.strip() != mission["owner"]:
        raise ProductMissionError(
            "MISSION_DECISION_OWNER_MISMATCH",
            "decision owner must match the mission owner",
        )
    if decision not in MISSION_DECISIONS:
        raise ProductMissionError(
            "DECISION_INVALID",
            f"decision must be one of {', '.join(sorted(MISSION_DECISIONS))}",
        )
    if not rationale.strip() or len(rationale) > MAX_NOTES:
        raise ProductMissionError(
            "RATIONALE_INVALID",
            f"rationale is required and limited to {MAX_NOTES} characters",
        )
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
        "markers": [
            "MISSION_EXECUTION_APPROVAL_BOUND",
            "EXTERNAL_EFFECTS_APPROVAL_REQUIRED",
        ],
    }
    receipt = {
        **core,
        "decision_sha256": _sha_bytes(_canonical(core)),
        "generated_at": _now(),
    }
    path = (
        Path(root).resolve()
        / ".factory"
        / "missions"
        / mission["id"]
        / "execution_decision.json"
    )
    _atomic_json(path, receipt, force=force)
    return {**receipt, "path": str(path)}


def _candidate_reject(message: str) -> None:
    raise ProductMissionError("MISSION_CANDIDATE_INVALID", message)


def _candidate_relative(value: Any, *, workspace: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        _candidate_reject("candidate paths must be explicit relative file names")
    parts = value.split("/")
    reserved = {"", ".", "..", ".git", ".factory"}
    checked_parts = (
        parts[2:] if workspace and parts[:2] == [".factory", "worktrees"] else parts
    )
    if any(
        part.casefold() in reserved or part != part.rstrip(" .")
        for part in checked_parts
    ):
        _candidate_reject("candidate path contains a reserved or escaping segment")
    if any(char in value for char in "\\:*?[]\x00\r\n"):
        _candidate_reject(
            "candidate paths cannot contain drives, globs or control characters"
        )
    return value


def _candidate_inside(root: Path, value: str, *, workspace: bool = False) -> Path:
    relative = _candidate_relative(value, workspace=workspace)
    path = root / relative
    for part in [path, *path.parents]:
        if part == root:
            break
        if part.is_symlink() or (
            part.exists() and getattr(part.lstat(), "st_file_attributes", 0) & 0x400
        ):
            _candidate_reject("candidate paths cannot traverse links or reparse points")
        if part != path and part.exists() and not part.is_dir():
            _candidate_reject("candidate path ancestors must be directories")
    if not path.resolve().is_relative_to(root):
        _candidate_reject("candidate path escapes its declared root")
    return path


def _candidate_git(workspace: Path, args: list[str]) -> str:
    result = run_cli_detailed(
        "git",
        [
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(workspace),
            *args,
        ],
        workspace,
        timeout=10,
        max_stream_bytes=1_000_000,
    )
    if not (
        result.get("ok")
        and result.get("cleanup_confirmed")
        and result.get("streams_closed")
    ):
        raise ProductMissionError(
            "MISSION_CANDIDATE_INVALID", "candidate Git facts unavailable"
        )
    stdout = result.get("stdout")
    if not isinstance(stdout, bytes):
        raise ProductMissionError(
            "MISSION_CANDIDATE_INVALID", "candidate Git facts unavailable"
        )
    return stdout.decode("utf-8", errors="replace").strip()


def _candidate_revision(workspace: Path, base: Any) -> None:
    if not isinstance(base, str) or not re.fullmatch(r"[0-9a-f]{40}", base):
        _candidate_reject("base_commit must be an exact Git commit SHA")
    if (
        Path(_candidate_git(workspace, ["rev-parse", "--show-toplevel"])).resolve()
        != workspace
    ):
        _candidate_reject("candidate must be its own Git workspace")
    if _candidate_git(workspace, ["rev-parse", "HEAD"]) != base:
        _candidate_reject("candidate HEAD differs from the approved base_commit")
    if _candidate_git(
        workspace, ["status", "--porcelain=v1", "--untracked-files=normal"]
    ):
        _candidate_reject("candidate must be clean before binding")


def _candidate_strings(value: Any, label: str, *, unique: bool = True) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 100:
        _candidate_reject(f"{label} requires one to 100 explicit entries")
    if any(
        not isinstance(item, str)
        or not item.strip()
        or len(item) > 2000
        or "\x00" in item
        for item in value
    ):
        _candidate_reject(f"{label} entries must be nonempty bounded strings")
    if unique and len(set(value)) != len(value):
        _candidate_reject(f"{label} entries must be unique")
    return value


def _candidate_commands(value: Any) -> None:
    if not isinstance(value, list) or not 1 <= len(value) <= 20:
        _candidate_reject("commands requires one to 20 argument vectors")
    identifiers = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"id", "argv"}:
            _candidate_reject("commands must contain only id and argv")
        identifier = item["id"]
        if not isinstance(identifier, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{1,64}", identifier
        ):
            _candidate_reject("command id must be a bounded identifier")
        _candidate_strings(item["argv"], "command argv", unique=False)
        identifiers.append(identifier)
    if len(set(identifiers)) != len(identifiers):
        _candidate_reject("command identifiers must be unique")


def _candidate_lanes(value: Any) -> None:
    lanes = {"static", "secrets", "configuration", "dependencies", "runtime", "fuzz"}
    if not isinstance(value, dict) or set(value) != lanes:
        _candidate_reject("declare applicability for all six audit lanes")
    for item in value.values():
        if not isinstance(item, dict) or set(item) != {"applicable", "reason"}:
            _candidate_reject("audit lanes require applicable and reason")
        if type(item["applicable"]) is not bool:
            _candidate_reject("audit lane applicability must be Boolean")
        _candidate_strings([item["reason"]], "audit lane reason")


def _candidate_declaration(
    root: Path, declaration: dict[str, Any]
) -> tuple[Path, list[dict[str, Any]]]:
    keys = {
        "schema",
        "workspace",
        "base_commit",
        "paths",
        "interfaces",
        "profiles",
        "commands",
        "audit_lanes",
    }
    if not isinstance(declaration, dict) or set(declaration) != keys:
        _candidate_reject("candidate declaration fields are invalid")
    if declaration["schema"] != "factory.mission.candidate-declaration.v1":
        _candidate_reject("candidate declaration schema is unsupported")
    workspace = _candidate_inside(
        root, declaration["workspace"], workspace=True
    ).resolve()
    _candidate_revision(workspace, declaration["base_commit"])
    paths = _candidate_strings(declaration["paths"], "permitted paths")
    files = [_candidate_file(workspace, value) for value in paths]
    _candidate_strings(declaration["interfaces"], "interfaces")
    _candidate_strings(declaration["profiles"], "execution profiles")
    _candidate_commands(declaration["commands"])
    _candidate_lanes(declaration["audit_lanes"])
    _candidate_revision(workspace, declaration["base_commit"])
    return workspace, files


def _candidate_file(workspace: Path, value: str) -> dict[str, Any]:
    path = _candidate_inside(workspace, value)
    if not path.exists():
        return {"path": value, "sha256": None, "state": "planned_new"}
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
        _candidate_reject("candidate scope must contain regular files at most 16 MiB")
    return {"path": value, "sha256": _sha_path(path), "state": "existing"}


def _candidate_approval(
    mission_path: Path, decision_path: Path, owner: str
) -> tuple[dict, dict]:
    if not verify_mission(mission_path)["valid"]:
        _candidate_reject("mission is no longer verified")
    mission = _load_mission(mission_path)
    decision = _load_json(decision_path, MISSION_DECISION_SCHEMA)
    core = {
        key: value
        for key, value in decision.items()
        if key not in {"decision_sha256", "generated_at"}
    }
    if _sha_bytes(_canonical(core)) != decision.get("decision_sha256"):
        _candidate_reject("execution decision hash differs")
    if decision.get("owner") != owner or mission["owner"] != owner:
        _candidate_reject("candidate binding requires the mission owner")
    expected = {
        "path": str(mission_path),
        "file_sha256": _sha_path(mission_path),
        "mission_sha256": mission["mission_sha256"],
    }
    if (
        decision.get("mission") != expected
        or decision.get("mission_id") != mission["id"]
    ):
        _candidate_reject("execution decision does not bind the current mission")
    if (
        decision.get("decision") != "approved_execution"
        or decision.get("execution_authorized") is not True
    ):
        _candidate_reject("candidate binding requires approved execution")
    return mission, decision


def _candidate_binding_core(
    mission_path: Path,
    decision_path: Path,
    root: Path,
    *,
    owner: str,
    declaration: dict[str, Any],
) -> dict[str, Any]:
    """Reconstruct a binding from live local facts without writing evidence."""
    root = Path(root).resolve()
    mission_path = Path(mission_path).resolve()
    decision_path = Path(decision_path).resolve()
    if not mission_path.is_relative_to(root) or not decision_path.is_relative_to(root):
        _candidate_reject(
            "mission and decision must be contained in the owner workspace"
        )
    mission, decision = _candidate_approval(mission_path, decision_path, owner)
    workspace, files = _candidate_declaration(root, declaration)
    return {
        "schema": CANDIDATE_BINDING_SCHEMA,
        "state": "bound_not_executed",
        "owner": owner,
        "mission": decision["mission"],
        "decision": {
            "path": str(decision_path),
            "sha256": decision["decision_sha256"],
            "file_sha256": _sha_path(decision_path),
        },
        "workspace": str(workspace),
        "declaration": declaration,
        "files": files,
        "candidate_sha256": _sha_bytes(
            _canonical({"base_commit": declaration["base_commit"], "files": files})
        ),
        "budgets": mission["budgets"],
        "execution_authorized": False,
        "dispatched": False,
        "limits": [
            "Snapshot binding only; revalidate before execution. No process isolation or executor is supplied.",
            "Lane applicability is an owner declaration, not executed audit evidence.",
        ],
    }


def bind_mission_candidate(
    mission_path: Path,
    decision_path: Path,
    root: Path,
    *,
    owner: str,
    declaration: dict[str, Any],
) -> dict[str, Any]:
    """Bind approved scope to a clean Git candidate; never launch commands."""
    core = _candidate_binding_core(
        mission_path, decision_path, root, owner=owner, declaration=declaration
    )
    digest = _sha_bytes(_canonical(core))
    path = (
        Path(core["mission"]["path"]).parent / f"candidate-binding-{digest[:16]}.json"
    )
    receipt = {**core, "binding_sha256": digest}
    _atomic_json(path, receipt)
    return {**receipt, "path": str(path)}


def verify_mission_candidate(
    binding_path: Path, root: Path, *, owner: str
) -> dict[str, Any]:
    """Recheck persisted scope and current Git/file facts without dispatch or writes."""
    root = Path(root).resolve()
    binding_path = Path(binding_path).resolve()
    if not binding_path.is_relative_to(root):
        _candidate_reject("candidate binding must be beneath the owner workspace")
    binding = _load_json(binding_path, CANDIDATE_BINDING_SCHEMA)
    core = {key: value for key, value in binding.items() if key != "binding_sha256"}
    if _sha_bytes(_canonical(core)) != binding.get("binding_sha256"):
        _candidate_reject("candidate binding hash differs")
    try:
        expected = _candidate_binding_core(
            Path(binding["mission"]["path"]),
            Path(binding["decision"]["path"]),
            root,
            owner=owner,
            declaration=binding["declaration"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        _candidate_reject(f"candidate binding cannot be verified: {type(exc).__name__}")
    if core != expected:
        _candidate_reject(
            "candidate binding differs from current approved scope or source facts"
        )
    return {
        "schema": "factory.mission.candidate-verification.v1",
        "valid": True,
        "state": "bound_not_executed",
        "binding_sha256": binding["binding_sha256"],
        "candidate_sha256": binding["candidate_sha256"],
        "execution_authorized": False,
        "dispatched": False,
        "limits": binding["limits"],
    }


def _mission_repair_snapshot(binding_path: Path, root: Path, owner: str) -> dict:
    verification = verify_mission_candidate(binding_path, root, owner=owner)
    binding = _load_json(binding_path, CANDIDATE_BINDING_SCHEMA)
    core = {key: value for key, value in binding.items() if key != "binding_sha256"}
    if _sha_bytes(_canonical(core)) != verification["binding_sha256"]:
        _candidate_reject("candidate binding changed during repair verification")
    return binding


def _mission_repair_scope(binding: dict, approval: dict) -> None:
    declaration = binding["declaration"]
    if (
        approval["workspace"] != str(Path(binding["workspace"])).casefold()
        or approval["base_commit"] != declaration["base_commit"]
    ):
        _candidate_reject("repair approval belongs to another workspace or Git base")
    paths = approval["touched_paths"]
    if not paths or not set(paths).issubset(declaration["paths"]):
        _candidate_reject("repair patch exceeds the approved mission paths")
    if "docker-linux" not in declaration["profiles"]:
        _candidate_reject(
            "mission must explicitly declare the docker-linux execution profile"
        )


def _mission_repair_tools(binding: dict, approval: dict) -> None:
    contract = approval["tool_contract"]
    permitted = {tuple(row["argv"]) for row in binding["declaration"]["commands"]}
    checks = contract["checks"]
    if not checks or any(tuple(check["argv"]) not in permitted for check in checks):
        _candidate_reject(
            "repair commands exceed the approved mission command manifest"
        )
    if contract["total_timeout_seconds"] > binding["budgets"]["max_wall_seconds"]:
        _candidate_reject("repair lifecycle exceeds the mission wall-time budget")


def verify_mission_repair_binding(
    binding_path: Path, root: Path, *, owner: str, approval: dict
) -> dict[str, Any]:
    """Constrain an independently verified repair approval; never create one."""
    binding_path, root = Path(binding_path).resolve(), Path(root).resolve()
    binding = _mission_repair_snapshot(binding_path, root, owner)
    try:
        _mission_repair_scope(binding, approval)
        _mission_repair_tools(binding, approval)
    except ProductMissionError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        _candidate_reject(f"repair contract cannot be matched: {type(exc).__name__}")
    mission = _load_mission(Path(binding["mission"]["path"]))
    passport = json.loads(
        Path(mission["loop"]["passport_path"]).read_text(encoding="utf-8")
    )
    if passport.get("budgets") != binding["budgets"]:
        _candidate_reject("mission budgets differ from the runtime passport")
    return {
        "schema": "factory.mission.repair-binding.v1",
        "path": str(binding_path),
        "root": str(root),
        "owner": owner,
        "workspace": binding["workspace"],
        "binding_sha256": binding["binding_sha256"],
        "binding_file_sha256": _sha_path(binding_path),
        "candidate_sha256": binding["candidate_sha256"],
        "mission_sha256": binding["mission"]["mission_sha256"],
        "decision_sha256": binding["decision"]["sha256"],
        "budget_passport_path": mission["loop"]["passport_path"],
    }


def execute_mission_repair(
    binding_path: Path, approval_path: Path, root: Path, *, owner: str
) -> dict[str, Any]:
    """Dispatch the existing isolated executor with a separate exact repair approval."""
    from .repair_sandbox import execute_approved_repair

    binding_path, root = Path(binding_path).resolve(), Path(root).resolve()
    binding = _mission_repair_snapshot(binding_path, root, owner)
    return execute_approved_repair(
        Path(binding["workspace"]),
        Path(approval_path),
        mission_binding={"path": str(binding_path), "root": str(root), "owner": owner},
    )


def _evidence(root: Path, paths: list[Path]) -> list[dict[str, Any]]:
    root = Path(root).resolve()
    result = []
    for value in paths:
        path = Path(value).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ProductMissionError(
                "EVIDENCE_OUTSIDE_ROOT", f"evidence must be beneath {root}: {path}"
            ) from exc
        if not path.is_file():
            raise ProductMissionError(
                "EVIDENCE_MISSING", f"evidence file not found: {path}"
            )
        result.append(
            {"path": str(path), "sha256": _sha_path(path), "bytes": path.stat().st_size}
        )
    return result


def _review_evidence(evidence: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    categories = {
        name: []
        for name in (
            "screenshots",
            "responsive",
            "accessibility",
            "tests",
            "mutations",
            "gates",
            "traces",
        )
    }
    for item in evidence:
        name = Path(item["path"]).name.lower()
        if any(
            word in name for word in ("screenshot", ".png", ".jpg", ".jpeg", ".webp")
        ):
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
        raise ProductMissionError(
            "VALIDATION_OUTSIDE_ROOT",
            f"validation manifest must be beneath {Path(root).resolve()}",
        ) from exc
    value = _load_json(resolved, MISSION_VALIDATION_INPUT_SCHEMA)
    for field in ("creator_id", "verifier_id"):
        if (
            not isinstance(value.get(field), str)
            or not value[field].strip()
            or len(value[field]) > 120
        ):
            raise ProductMissionError(
                "NO_FINISH_CONTRACT",
                f"{field} is required and limited to 120 characters",
            )
    return value, resolved


def _validate_context_wall(mission: dict[str, Any], manifest: dict[str, Any]) -> None:
    if manifest["creator_id"].strip() == manifest["verifier_id"].strip():
        raise ProductMissionError(
            "VERIFIER_IDENTITY_DISTINCT", "creator and verifier identities must differ"
        )
    contexts = manifest.get("verifier_context")
    required = {"mission.json", "candidate_diff", "evidence_manifest"}
    allowed = required | {"test_output", "browser_artifact", "architecture_receipt"}
    forbidden = set(
        mission["orchestration"]["context_wall"]["verifier_forbidden_inputs"]
    )
    if (
        not isinstance(contexts, list)
        or not all(isinstance(item, str) for item in contexts)
        or not required.issubset(contexts)
        or not set(contexts).issubset(allowed)
        or forbidden.intersection(contexts)
    ):
        raise ProductMissionError(
            "CREATOR_VERIFIER_CONTEXT_WALL",
            "verifier context must contain only review inputs and exclude creator-private context",
        )
    if (
        mission["orchestration"]["attempt_policy"].get("adapter_attestation_required")
        is True
    ):
        raw = manifest.get("adapter_attestation")
        if not isinstance(raw, dict):
            raise ProductMissionError(
                "VERIFIER_ADAPTER_ATTESTATION_REQUIRED",
                "fresh adapter attestation is required before mission completion",
            )
        try:
            validate_verifier_attestation(raw, mission_digest=mission["mission_sha256"])
        except AgentContractError as exc:
            raise ProductMissionError(exc.code, exc.message) from exc


def _browser_flow_artifacts(
    mission: dict[str, Any],
    criterion: dict[str, Any],
    evidence_path: Path,
    verifier_id: str,
    root: Path,
) -> tuple[list[Path], dict[str, Any]]:
    evidence_path = evidence_path.resolve()
    try:
        evidence_path.relative_to(Path(root).resolve())
    except ValueError as exc:
        raise ProductMissionError(
            "BROWSER_FLOW_INVALID", "browser evidence must be beneath the mission root"
        ) from exc
    evidence = _load_json(evidence_path, "factory.browser-flow.evidence.v1")
    contract = criterion["evidence_contract"]
    errors = _browser_flow_identity_errors(evidence, mission, criterion, verifier_id)
    clicks = evidence.get("clicks")
    errors.extend(_browser_flow_interaction_errors(evidence, contract, clicks))
    assertions = evidence.get("assertions")
    errors.extend(_browser_flow_assertion_errors(assertions))
    artifacts, artifact_errors = _resolve_browser_artifacts(
        evidence.get("artifacts"), root
    )
    errors.extend(artifact_errors)
    if errors:
        raise ProductMissionError("BROWSER_FLOW_INVALID", "; ".join(errors))
    return artifacts, {
        "expected_url": evidence.get("expected_url"),
        "observed_url": evidence.get("observed_url"),
        "clicks": clicks,
        "max_clicks": contract["max_clicks"],
        "assertions": len(assertions),
    }


def _browser_flow_identity_errors(
    evidence: dict[str, Any],
    mission: dict[str, Any],
    criterion: dict[str, Any],
    verifier_id: str,
) -> list[str]:
    errors = []
    if (
        evidence.get("mission_id") != mission["id"]
        or evidence.get("criterion_id") != criterion["id"]
    ):
        errors.append("mission or criterion id mismatch")
    if evidence.get("verifier_id") != verifier_id:
        errors.append("browser verifier must match the independent validation manifest")
    expected = evidence.get("expected_url")
    observed = evidence.get("observed_url")
    if not isinstance(expected, str) or not expected or observed != expected:
        errors.append("observed URL does not exactly match the declared expected URL")
    return errors


def _browser_flow_interaction_errors(
    evidence: dict[str, Any], contract: dict[str, Any], clicks: Any
) -> list[str]:
    errors = []
    steps = evidence.get("steps")
    if (
        isinstance(clicks, bool)
        or not isinstance(clicks, int)
        or clicks < 0
        or clicks > contract["max_clicks"]
    ):
        errors.append(f"click count must be between 0 and {contract['max_clicks']}")
    if (
        not isinstance(steps, list)
        or not isinstance(clicks, int)
        or len(steps) != clicks
        or any(
            not isinstance(item, dict) or item.get("passed") is not True
            for item in steps
        )
    ):
        errors.append("every counted browser interaction must have one passing step")
    return errors


def _browser_flow_assertion_errors(assertions: Any) -> list[str]:
    errors = []
    if (
        not isinstance(assertions, list)
        or not assertions
        or any(
            not isinstance(item, dict) or item.get("passed") is not True
            for item in assertions
        )
    ):
        errors.append("every declared browser assertion must pass")
    return errors


def _resolve_browser_artifacts(
    artifacts: Any, root: Path
) -> tuple[list[Path], list[str]]:
    errors = []
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("at least one screenshot or browser artifact is required")
        artifacts = []
    resolved = []
    for value in artifacts:
        if not isinstance(value, str) or not value.strip():
            errors.append("browser artifact paths must be non-empty strings")
            continue
        path = (
            Path(value) if Path(value).is_absolute() else Path(root).resolve() / value
        )
        try:
            path.resolve().relative_to(Path(root).resolve())
        except ValueError:
            errors.append(f"browser artifact is outside the mission root: {path}")
            continue
        if not path.is_file():
            errors.append(f"browser artifact is missing: {path}")
        else:
            resolved.append(path.resolve())
    return resolved, errors


def _validated_completion_results(
    mission: dict[str, Any], manifest: dict[str, Any], root: Path
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    criteria_by_id = {
        item["id"]: item for item in mission["completion_contract"]["criteria"]
    }
    results = _completion_result_list(manifest)
    _validate_completion_coverage(results, list(criteria_by_id))
    evidence_paths: list[Path] = []
    normalized = []
    for item in results:
        normalized_item, item_paths = _validated_completion_item(
            item, criteria_by_id[item["id"]], mission, manifest, root
        )
        evidence_paths.extend(item_paths)
        normalized.append(normalized_item)
    unique = list(dict.fromkeys(path.resolve() for path in evidence_paths))
    if len(unique) > MAX_COMPLETION_EVIDENCE:
        raise ProductMissionError(
            "NO_FINISH_CONTRACT",
            f"completion evidence is limited to {MAX_COMPLETION_EVIDENCE} files",
        )
    return normalized, _evidence(Path(root), unique)


def _daily_verification_summary(
    contract: Any,
    mission: dict[str, Any],
    root: Path,
    *,
    mission_path: Path | None = None,
) -> tuple[dict[str, Any], list[Path]]:
    if contract is _DAILY_VERIFICATION_UNSET:
        return (
            {
                "schema": DAILY_VERIFICATION_SCHEMA,
                "status": "LEGACY_CLAIMED",
                "complete": False,
                "execution_verified": False,
                "attestation_verified": False,
                "command_pair_receipts_verified": False,
                "behavioral_verification": "unverified",
                "gaps": ["daily_verification_contract_missing"],
                "criteria": [],
            },
            [],
        )

    gaps: list[str] = []
    evidence_paths: list[Path] = []
    if not isinstance(contract, dict):
        return _daily_verification_incomplete("contract_malformed"), []
    allowed = {
        "schema",
        "candidate_sha256",
        "source_manifest",
        "scope_closure",
        "criteria",
    }
    if set(contract) != allowed or contract.get("schema") != DAILY_VERIFICATION_SCHEMA:
        gaps.append("contract_malformed")

    source_rows, source_digest, source_paths = _daily_source_manifest(
        contract.get("source_manifest"), root, gaps
    )
    candidate_claim = contract.get("candidate_sha256")
    if candidate_claim != source_digest:
        gaps.append("candidate_binding_mismatch")
    if contract.get("scope_closure") != "declared_only":
        gaps.append("candidate_scope_closure_claim_unverified")
    oracle_cache: dict[tuple[str, str, str, str], dict[str, Any] | None] = {}

    expected_criteria = {
        item["id"] for item in mission["completion_contract"]["criteria"]
    }
    criteria_rows, case_paths = _daily_criteria(
        contract.get("criteria"),
        expected_criteria,
        source_rows,
        root,
        gaps,
        oracle_cache,
        mission,
        candidate_claim,
        mission_path,
    )
    receipt_gaps = (
        "execution_evidence_",
        "execution_infrastructure_",
        "execution_receipt_",
        "execution_artifact_",
        "execution_candidate_source_",
    )
    receipts_verified = (
        bool(criteria_rows)
        and not any(gap.startswith(receipt_gaps) for gap in gaps)
        and all(
            case["disposition"] == "command_pair_observed"
            for criterion in criteria_rows
            for case in criterion["cases"]
        )
    )
    all_cases = [case for criterion in criteria_rows for case in criterion["cases"]]
    if not _daily_oracle_case_ids_unique(all_cases):
        gaps.append("execution_oracle_case_reused")
    execution_verified = False
    attestation_verified = bool(all_cases) and all(
        case["disposition"] == "signer_attested_baseline_and_mutant"
        for case in all_cases
    )
    local_execution_observed = bool(all_cases) and all(
        case["disposition"]
        in {
            "local_mutation_target_observed",
            "local_mutation_control_observed",
        }
        for case in all_cases
    )
    has_local_execution = any(
        case["disposition"]
        in {
            "local_mutation_target_observed",
            "local_mutation_control_observed",
        }
        for case in all_cases
    )
    has_signer_claims = any(
        case["disposition"] == "signer_attested_baseline_and_mutant"
        for case in all_cases
    )
    if not local_execution_observed and "behavioral_assertion_unverified" not in gaps:
        gaps.append("behavioral_assertion_unverified")
    complete = not gaps
    evidence_paths.extend(source_paths)
    evidence_paths.extend(case_paths)
    return (
        {
            "schema": DAILY_VERIFICATION_SCHEMA,
            "status": "COMPLETE" if complete else "INCOMPLETE",
            "complete": complete,
            "execution_verified": execution_verified,
            "attestation_verified": attestation_verified,
            "command_pair_receipts_verified": receipts_verified,
            "local_execution_observed": local_execution_observed,
            "local_execution_trust_boundary": (
                "Explicit operator-invoked local subprocess observations; persisted hashes prove currentness and binding only, not unforgeable host origin, independent attestation, or application correctness."
            )
            if local_execution_observed
            else None,
            "behavioral_verification": "local_assertions_observed"
            if local_execution_observed
            else "unverified",
            "attestation_claim_boundary": (
                "Signature verification validates signer claims only; it does not establish "
                "independent test execution, mutation application, or oracle accuracy."
            )
            if attestation_verified
            else None,
            "candidate_sha256_claim": candidate_claim,
            "candidate_sha256": source_digest,
            "scope_closure_claim": contract.get("scope_closure"),
            "scope_closure": "declared_verified_scope",
            "scope_limitations": [
                "Repository-wide changed-file closure is not established.",
                *(
                    [
                        "Local execution was observed under the writable-host assumption; it is not independently attested."
                    ]
                    if has_local_execution
                    else []
                ),
                *(
                    [
                        "The execution environment is signer-claimed, not independently remeasured at completion."
                    ]
                    if has_signer_claims
                    else []
                ),
                *(
                    [
                        "The execution environment was not independently remeasured at completion."
                    ]
                    if not has_local_execution and not has_signer_claims
                    else []
                ),
            ],
            "source_manifest": source_rows,
            "criteria": criteria_rows,
            "gaps": sorted(set(gaps)),
        },
        evidence_paths,
    )


def _daily_oracle_case_ids_unique(cases: list[dict[str, Any]]) -> bool:
    identities = [
        (
            case.get("execution_receipt_sha256"),
            case.get("oracle_test_path"),
            case.get("oracle_test_line"),
            case.get("oracle_test_symbol"),
            case.get("oracle_case_id"),
        )
        for case in cases
        if case.get("disposition") == "signer_attested_baseline_and_mutant"
    ]
    return len(identities) == len(set(identities))


def _daily_verification_incomplete(gap: str) -> dict[str, Any]:
    return {
        "schema": DAILY_VERIFICATION_SCHEMA,
        "status": "INCOMPLETE",
        "complete": False,
        "execution_verified": False,
        "attestation_verified": False,
        "command_pair_receipts_verified": False,
        "local_execution_observed": False,
        "local_execution_trust_boundary": None,
        "behavioral_verification": "unverified",
        "gaps": [gap],
        "criteria": [],
    }


def _daily_source_manifest(
    value: Any, root: Path, gaps: list[str]
) -> tuple[list[dict[str, str]], str | None, list[Path]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_COMPLETION_EVIDENCE:
        gaps.append("candidate_source_manifest_missing_or_unbounded")
        return [], None, []
    rows, paths = [], []
    total_bytes = 0
    seen = set()
    for item in value:
        identity = _daily_source_identity(item, gaps)
        if identity is None:
            continue
        path_text, digest = identity
        resolved = _daily_source_path(path_text, root, seen, gaps)
        if resolved is None:
            continue
        normalized, path = resolved
        row = {"path": normalized, "sha256": digest}
        rows.append(row)
        seen.add(normalized)
        total_bytes = _check_daily_source_file(
            path, normalized, digest, total_bytes, paths, gaps
        )
    rows.sort(key=lambda row: row["path"])
    if len(rows) != len(value):
        return rows, None, paths
    return rows, _sha_bytes(_canonical(rows)), paths


def capture_mission_local_mutation(
    mission_path: Path,
    daily_contract_path: Path,
    root: Path,
    criterion_id: str,
    target_case_id: str,
    control_case_id: str,
    target_selector: str,
    target_line: int,
    control_selector: str,
    control_line: int,
    production_path: str,
    production_symbol: str,
    before_text: str,
    after_text: str,
    evidence_path: str,
    *,
    timeout_seconds: int = 60,
    python_executable: Path | None = None,
) -> dict[str, Any]:
    """Explicitly run and bind one local mutation case and an unaffected control."""
    workspace = Path(root).resolve(strict=True)
    mission_file = _local_capture_input_path(mission_path, workspace)
    contract_file = _local_capture_input_path(daily_contract_path, workspace)
    mission = _load_mission(mission_file)
    if not verify_mission(mission_file)["valid"]:
        raise ProductMissionError("MISSION_INPUT_DRIFT", "mission is not current")
    contract, source_map, candidate_sha = _local_capture_contract(
        _load_json(contract_file, DAILY_VERIFICATION_SCHEMA), mission, workspace
    )
    contract_sha_before = _sha_path(contract_file)
    mission_sha_before = _sha_path(mission_file)
    target_case = _mission_capture_case(
        contract, criterion_id, target_case_id, "positive", source_map
    )
    control_case = _mission_capture_case(
        contract, criterion_id, control_case_id, "negative", source_map
    )
    _mission_capture_inputs(
        target_case,
        control_case,
        target_selector,
        control_selector,
        production_path,
        source_map,
    )
    evidence_dir = _local_capture_output_path(evidence_path, workspace)
    evidence_dir.mkdir(parents=True, exist_ok=False)
    contract_snapshot = evidence_dir / "daily-contract.before.json"
    contract_snapshot.write_bytes(contract_file.read_bytes())
    contract_snapshot_sha = _sha_path(contract_snapshot)
    from .runtime_audit_runner import capture_local_production_mutation

    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
        raise ProductMissionError(
            "LOCAL_CAPTURE_TIMEOUT", "timeout must be between 1 and 300 seconds"
        )
    deadline = time.monotonic() + 4 * timeout_seconds
    target_timeout = timeout_seconds

    target = capture_local_production_mutation(
        workspace,
        target_selector,
        target_line,
        production_path,
        production_symbol,
        before_text,
        after_text,
        str(evidence_dir / "target"),
        timeout_seconds=target_timeout,
        python_executable=python_executable,
    )
    remaining = deadline - time.monotonic()
    if remaining < 2:
        raise ProductMissionError(
            "LOCAL_CAPTURE_TIMEOUT", "overall target/control capture budget expired"
        )
    control_timeout = min(timeout_seconds, int(remaining // 2))
    control = capture_local_production_mutation(
        workspace,
        control_selector,
        control_line,
        production_path,
        production_symbol,
        before_text,
        after_text,
        str(evidence_dir / "control"),
        timeout_seconds=control_timeout,
        python_executable=python_executable,
    )
    record_path = evidence_dir / "mission-case.json"
    receipt = _mission_capture_receipt(
        mission,
        contract_file,
        contract,
        candidate_sha,
        criterion_id,
        target_case,
        control_case,
        target,
        control,
        record_path,
        workspace,
        mission_file,
        mission_sha_before,
        contract_sha_before,
        contract_snapshot,
        contract_snapshot_sha,
        4 * timeout_seconds,
        target_timeout,
        control_timeout,
    )
    if (
        _sha_path(mission_file) != mission_sha_before
        or _sha_path(contract_file) != contract_sha_before
    ):
        raise ProductMissionError(
            "DAILY_VERIFICATION_DRIFT", "inputs changed during capture"
        )
    _atomic_json(record_path, receipt)
    updated = _mission_capture_contract_evidence(
        contract, target_case_id, control_case_id, record_path, workspace
    )
    _atomic_json(contract_file, updated, force=True)
    return {**receipt, "path": str(record_path.resolve())}


def _local_capture_input_path(value: Path, root: Path) -> Path:
    path = Path(value)
    path = path if path.is_absolute() else root / path
    try:
        lexical = Path(os.path.abspath(path))
        lexical.relative_to(root)
        from .runtime_audit_process import regular_target_within

        if not regular_target_within(root, lexical):
            raise ValueError("input must be a regular workspace file")
        return lexical.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProductMissionError(
            "DAILY_VERIFICATION_DRIFT", "input is outside the workspace or unreadable"
        ) from exc


def _local_capture_output_path(value: str, root: Path) -> Path:
    from .runtime_audit_process import new_output_path_inside

    path = Path(value)
    path = path if path.is_absolute() else root / path
    try:
        new_output_path_inside(root, path)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProductMissionError(
            "DAILY_VERIFICATION_DRIFT", "evidence output must be new and contained"
        ) from exc
    return path


def _local_capture_contract(
    contract: dict[str, Any], mission: dict[str, Any], root: Path
) -> tuple[dict[str, Any], dict[str, str], str]:
    if (
        set(contract)
        != {
            "schema",
            "candidate_sha256",
            "source_manifest",
            "scope_closure",
            "criteria",
        }
        or contract.get("schema") != DAILY_VERIFICATION_SCHEMA
    ):
        raise ProductMissionError(
            "DAILY_VERIFICATION_DRIFT", "daily contract schema is invalid"
        )
    gaps: list[str] = []
    rows, candidate_sha, _ = _daily_source_manifest(
        contract.get("source_manifest"), root, gaps
    )
    source_map = {item["path"]: item["sha256"] for item in rows}
    expected = {item["id"] for item in mission["completion_contract"]["criteria"]}
    criteria = contract.get("criteria")
    actual = _local_capture_criterion_ids(criteria)
    case_ids = _local_capture_case_ids(criteria, source_map)
    if (
        contract.get("candidate_sha256") != candidate_sha
        or contract.get("scope_closure") != "declared_only"
        or actual != expected
        or len(case_ids) != len(set(case_ids))
        or gaps
    ):
        raise ProductMissionError(
            "DAILY_VERIFICATION_DRIFT", "daily contract is not current and complete"
        )
    return contract, {item["path"]: item["sha256"] for item in rows}, candidate_sha


def _local_capture_criterion_ids(criteria):
    if not isinstance(criteria, list):
        return set()
    if any(
        not isinstance(item, dict) or set(item) != {"criterion_id", "cases"}
        for item in criteria
    ):
        return set()
    return {item["criterion_id"] for item in criteria}


def _local_capture_case_ids(criteria, source_map):
    if not isinstance(criteria, list):
        return []
    identities = []
    for item in criteria:
        cases = item.get("cases") if isinstance(item, dict) else None
        if not isinstance(cases, list) or not 2 <= len(cases) <= 8:
            return []
        polarities = set()
        for case in cases:
            if not _local_capture_case_well_formed(case, source_map):
                return []
            polarities.add(case["polarity"])
            identities.append(case["case_id"])
        if polarities != {"positive", "negative"}:
            return []
    return identities


def _local_capture_case_well_formed(case, source_map):
    fields = {
        "case_id",
        "polarity",
        "input_paths",
        "input_sha256",
        "expected_outcome",
        "observed_outcome",
        "evidence",
    }
    if not isinstance(case, dict) or set(case) != fields:
        return False
    paths = case.get("input_paths")
    if not isinstance(case.get("case_id"), str) or not case["case_id"].strip():
        return False
    if case.get("polarity") not in {"positive", "negative"}:
        return False
    if (
        not isinstance(paths, list)
        or not paths
        or any(path not in source_map for path in paths)
    ):
        return False
    if len(paths) != len(set(paths)):
        return False
    rows = [{"path": path, "sha256": source_map[path]} for path in paths]
    if case.get("input_sha256") != _sha_bytes(_canonical(rows)):
        return False
    evidence = case.get("evidence")
    return evidence in ({}, None) or (
        isinstance(evidence, dict)
        and set(evidence) == {"kind", "path", "sha256", "role"}
        and evidence.get("kind") == "local_production_mutation"
        and evidence.get("role") in {"target", "control"}
    )


def _mission_capture_case(contract, criterion_id, case_id, polarity, source_map):
    criteria = {
        item.get("criterion_id"): item
        for item in contract["criteria"]
        if isinstance(item, dict)
    }
    criterion = criteria.get(criterion_id)
    cases = criterion.get("cases") if isinstance(criterion, dict) else None
    matches = (
        [
            item
            for item in cases
            if isinstance(item, dict) and item.get("case_id") == case_id
        ]
        if isinstance(cases, list)
        else []
    )
    if len(matches) != 1 or matches[0].get("polarity") != polarity:
        raise ProductMissionError(
            "DAILY_VERIFICATION_DRIFT", "case identity or polarity is not declared"
        )
    case = matches[0]
    expected_outcome = (
        "baseline_assertion_pass_mutant_assertion_fail"
        if polarity == "positive"
        else "baseline_assertion_pass_mutant_assertion_pass"
    )
    paths = case.get("input_paths")
    input_rows = (
        [
            {"path": path, "sha256": source_map[path]}
            for path in paths
            if isinstance(paths, list) and path in source_map
        ]
        if isinstance(paths, list)
        else []
    )
    if (
        not input_rows
        or len(input_rows) != len(paths)
        or case.get("input_sha256") != _sha_bytes(_canonical(input_rows))
        or case.get("expected_outcome") != expected_outcome
        or case.get("observed_outcome") != "unknown"
        or case.get("evidence") not in ({}, None)
    ):
        raise ProductMissionError(
            "DAILY_VERIFICATION_DRIFT", "case inputs are stale or already captured"
        )
    return case


def _mission_capture_inputs(
    target, control, target_selector, control_selector, production_path, source_map
):
    if (
        target_selector == control_selector
        or not isinstance(production_path, str)
        or production_path not in source_map
        or target_selector.split("::", 1)[0] not in target.get("input_paths", [])
        or control_selector.split("::", 1)[0] not in control.get("input_paths", [])
        or production_path not in target.get("input_paths", [])
        or production_path not in control.get("input_paths", [])
    ):
        raise ProductMissionError(
            "DAILY_VERIFICATION_DRIFT",
            "target, control, and candidate inputs must be explicitly bound",
        )


def _mission_capture_receipt(
    mission,
    contract_file,
    contract,
    candidate_sha,
    criterion_id,
    target_case,
    control_case,
    target,
    control,
    record_path,
    root,
    mission_file,
    mission_sha_before,
    contract_sha_before,
    contract_snapshot,
    contract_snapshot_sha,
    overall_timeout,
    target_timeout,
    control_timeout,
):
    from .runtime_audit_runner import project_local_production_mutation_v3_candidate

    target_path = record_path.parent / "target" / "capture.json"
    control_path = record_path.parent / "control" / "capture.json"
    target_saved, control_saved = (
        _read_local_capture(target_path),
        _read_local_capture(control_path),
    )
    target_projection = project_local_production_mutation_v3_candidate(target_saved)
    if target_projection.get("status") != "CANDIDATE":
        raise ProductMissionError(
            "LOCAL_CAPTURE_INCOMPLETE",
            "target capture lacks a complete natural assertion failure",
        )
    control_status = _validate_unaffected_control_capture(
        control_saved, target_saved, root
    )
    if not control_status:
        raise ProductMissionError(
            "LOCAL_CAPTURE_INCOMPLETE",
            "unaffected control did not pass under the same mutation",
        )
    if not _validate_target_local_capture(target_saved, root):
        raise ProductMissionError(
            "LOCAL_CAPTURE_INCOMPLETE",
            "target capture is stale or its natural assertion is unbound",
        )
    target_digest, control_digest = _sha_path(target_path), _sha_path(control_path)
    return {
        "schema": "factory.mission.local-mutation-capture.v1",
        "status": "OBSERVED",
        "authority": "none",
        "local_execution_observed": True,
        "claim_boundary": "Explicit operator-invoked local process observation under the writable-host trust assumption; unsigned and not independently attested, not proof of application correctness, and grants no merge, publish, deploy, or release authority.",
        "mission_id": mission["id"],
        "mission_sha256": mission["mission_sha256"],
        "mission_path": mission_file.relative_to(root).as_posix(),
        "mission_file_sha256": mission_sha_before,
        "daily_contract_path": contract_file.relative_to(root).as_posix(),
        "daily_contract_sha256_before_capture": contract_sha_before,
        "daily_contract_snapshot": {
            "path": contract_snapshot.relative_to(root).as_posix(),
            "sha256": contract_snapshot_sha,
        },
        "candidate_sha256": candidate_sha,
        "criterion_id": criterion_id,
        "target_case": _mission_capture_case_binding(
            target_case, "positive", target_path, target_digest
        ),
        "control_case": _mission_capture_case_binding(
            control_case, "negative", control_path, control_digest
        ),
        "target_capture": {
            "path": target_path.relative_to(root).as_posix(),
            "sha256": target_digest,
        },
        "control_capture": {
            "path": control_path.relative_to(root).as_posix(),
            "sha256": control_digest,
        },
        "source_manifest_sha256": target_saved.get("source_manifest_sha256"),
        "production_mutation": target_saved.get("production_mutation"),
        "configuration_context_sha256": target_saved.get(
            "configuration_context_sha256"
        ),
        "captures_same_candidate_and_mutation": _capture_pair_same_inputs(
            target_saved, control_saved
        ),
        "execution_budget": {
            "overall_timeout_seconds": overall_timeout,
            "target_child_timeout_seconds": target_timeout,
            "control_child_timeout_seconds": control_timeout,
            "maximum_child_processes": 4,
        },
    }


def _mission_capture_case_binding(case, polarity, path, digest):
    return {
        "case_id": case["case_id"],
        "polarity": polarity,
        "input_paths": list(case["input_paths"]),
        "input_sha256": case["input_sha256"],
        "expected_outcome": "baseline_assertion_pass_mutant_assertion_fail"
        if polarity == "positive"
        else "baseline_assertion_pass_mutant_assertion_pass",
        "evidence_path": path.name,
        "evidence_sha256": digest,
    }


def _read_local_capture(path):
    try:
        from .runtime_audit_process import bounded_file_sha256

        _, data = bounded_file_sha256(path, MAX_DAILY_RECEIPT_BYTES, include_bytes=True)
        value = json.loads(data.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("capture must be an object")
        return value
    except (OSError, UnicodeError, ValueError) as exc:
        raise ProductMissionError(
            "LOCAL_CAPTURE_INCOMPLETE", "local capture is unreadable or oversized"
        ) from exc


def _capture_pair_same_inputs(target, control):
    return (
        all(
            target.get(key) == control.get(key)
            for key in (
                "source_manifest",
                "source_manifest_sha256",
                "production_mutation",
                "configuration_context_sha256",
            )
        )
        and target.get("status") == "OBSERVED"
        and control.get("status") == "INCOMPLETE"
    )


def _validate_unaffected_control_capture(control, target, root):
    from .runtime_audit_common import validate_production_mutation_trial
    from .runtime_audit_process import validate_production_mutation_process
    from .runtime_audit_runner import _candidate_manifest

    try:
        manifest = _candidate_manifest(control)
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
    selection, mutation = (
        control.get("selection", {}),
        control.get("production_mutation", {}),
    )
    selector, line = selection.get("nodeid_selector"), selection.get("assertion_line")
    if not _capture_pair_same_inputs(target, control) or not control.get(
        "source_unchanged"
    ):
        return False
    if (
        not isinstance(control.get("cleanup"), dict)
        or control["cleanup"].get("removed") is not True
    ):
        return False
    if not all(
        validate_production_mutation_process(control.get(name, {}).get("process", {}))
        and control[name]["process"].get("exit_code") == 0
        for name in ("baseline", "mutant")
    ):
        return False
    observations = [
        control.get("baseline_observation"),
        control.get("mutant_observation"),
    ]
    return (
        all(
            isinstance(item, dict)
            and validate_production_mutation_trial(
                item, selector, line, "passed", False
            )
            and _local_capture_observation_manifest(item, manifest, mutation, name)
            for item, name in zip(observations, ("baseline", "mutant"), strict=True)
        )
        and observations[0].get("collected") == observations[1].get("collected")
        and _local_capture_current_source(control, root, manifest)
        and _local_capture_current_source(target, root, manifest)
    )


def _validate_target_local_capture(target, root):
    from .runtime_audit_common import validate_production_mutation_trial
    from .runtime_audit_process import validate_production_mutation_process
    from .runtime_audit_runner import _candidate_manifest

    try:
        manifest = _candidate_manifest(target)
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
    selection = target.get("selection", {})
    selector, line = selection.get("nodeid_selector"), selection.get("assertion_line")
    baseline, mutant = target.get("baseline", {}), target.get("mutant", {})
    observations = [
        target.get("baseline_observation"),
        target.get("mutant_observation"),
    ]
    if not all(
        (
            target.get("status") == "OBSERVED",
            target.get("source_unchanged") is True,
            isinstance(target.get("cleanup"), dict),
            target["cleanup"].get("removed") is True,
            validate_production_mutation_process(baseline.get("process", {})),
            baseline["process"].get("exit_code") == 0,
            validate_production_mutation_process(mutant.get("process", {})),
            # The observer worker exits zero after recording a natural assertion
            # failure; the pytest outcome is carried in the bound trial record.
            mutant["process"].get("exit_code") == 0,
        )
    ):
        return False
    return (
        all(
            isinstance(item, dict)
            and validate_production_mutation_trial(
                item, selector, line, outcome, visible
            )
            and _local_capture_observation_manifest(
                item, manifest, target["production_mutation"], name
            )
            for item, name, outcome, visible in zip(
                observations,
                ("baseline", "mutant"),
                ("passed", "failed"),
                (False, True),
                strict=True,
            )
        )
        and observations[0].get("collected") == observations[1].get("collected")
        and _local_capture_current_source(target, root, manifest)
    )


def _local_capture_observation_manifest(observation, manifest, mutation, name):
    run_manifest = dict(manifest)
    if name == "mutant":
        run_manifest[mutation["path"]] = mutation["mutant_sha256"]
    digest = _sha_bytes(
        json.dumps(run_manifest, sort_keys=True, separators=(",", ":")).encode()
    )
    if observation.get("executed_source_manifest_sha256") != digest:
        return False
    cases = set(observation.get("collected", []))
    required_paths = {mutation.get("path"), *(case.split("::", 1)[0] for case in cases)}
    required = {(path, case) for path in required_paths for case in cases}
    rows = observation.get("executed_modules")
    found = set()
    if (
        not isinstance(rows, list)
        or observation.get("origin_status") != "BOUND"
        or observation.get("origin_limit_exceeded") is not False
    ):
        return False
    for row in rows:
        if not isinstance(row, dict) or row.get("phase") != "call":
            continue
        path, case = row.get("path"), row.get("nodeid")
        if not all(
            (
                case in cases,
                path in manifest,
                row.get("origin") == path,
                row.get("status") == "BOUND",
                row.get("observation_kind") == "executed_frame",
                row.get("source_sha256") == run_manifest.get(path),
            )
        ):
            return False
        found.add((path, case))
    return required <= found


def _local_capture_current_source(capture, root, manifest):
    from .pytest_readiness import (
        _challenge_runtime_context,
        _challenge_source_binding,
        _challenge_source_inventory,
    )

    try:
        return (
            _challenge_source_inventory(root) == manifest
            and capture.get("source_manifest_sha256") == _challenge_source_binding(root)
            and capture.get("configuration_context_sha256")
            == _challenge_runtime_context(root)
        )
    except (OSError, RuntimeError, ValueError):
        return False


def _mission_capture_contract_evidence(
    contract, target_id, control_id, record_path, root
):
    updated = json.loads(json.dumps(contract))
    for criterion in updated["criteria"]:
        for case in criterion["cases"]:
            if case["case_id"] in {target_id, control_id}:
                role = "target" if case["case_id"] == target_id else "control"
                outcome = (
                    "baseline_assertion_pass_mutant_assertion_fail"
                    if role == "target"
                    else "baseline_assertion_pass_mutant_assertion_pass"
                )
                case["observed_outcome"] = outcome
                case["evidence"] = {
                    "kind": "local_production_mutation",
                    "path": record_path.relative_to(root).as_posix(),
                    "sha256": _sha_path(record_path),
                    "role": role,
                }
    return updated


def _check_daily_source_file(
    path: Path,
    normalized: str,
    digest: str,
    total_bytes: int,
    paths: list[Path],
    gaps: list[str],
) -> int:
    try:
        if not path.is_file():
            gaps.append("candidate_source_stale:" + normalized)
            return total_bytes
        size = path.stat().st_size
        if size > MAX_DAILY_SOURCE_BYTES:
            gaps.append("candidate_source_size_limit:" + normalized)
        elif total_bytes + size > MAX_DAILY_TOTAL_SOURCE_BYTES:
            gaps.append("candidate_source_total_size_limit")
        else:
            total_bytes += size
            paths.append(path)
            if _sha_path(path) != digest:
                gaps.append("candidate_source_stale:" + normalized)
    except OSError:
        gaps.append("candidate_source_unreadable:" + normalized)
    return total_bytes


def _daily_source_identity(item: Any, gaps: list[str]) -> tuple[str, str] | None:
    if (
        not isinstance(item, dict)
        or set(item) != {"path", "sha256"}
        or not isinstance(item.get("path"), str)
        or not _valid_sha256(item.get("sha256"))
    ):
        gaps.append("candidate_source_manifest_malformed")
        return None
    path_text = item["path"].replace("\\", "/")
    if not path_text or path_text.startswith("/") or ".." in path_text.split("/"):
        gaps.append("candidate_source_path_invalid")
        return None
    return path_text, item["sha256"]


def _daily_source_path(
    path_text: str, root: Path, seen: set[str], gaps: list[str]
) -> tuple[str, Path] | None:
    try:
        path = (Path(root).resolve() / path_text).resolve()
        normalized = path.relative_to(Path(root).resolve()).as_posix()
    except (OSError, RuntimeError, ValueError):
        gaps.append("candidate_source_path_outside_root")
        return None
    if normalized in seen:
        gaps.append("candidate_source_path_duplicate")
        return None
    return normalized, path


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _daily_criteria(
    value: Any,
    expected: set[str],
    source_rows: list[dict[str, str]],
    root: Path,
    gaps: list[str],
    oracle_cache: dict[tuple[str, str, str, str], dict[str, Any] | None],
    mission: dict[str, Any],
    candidate_sha: str | None,
    mission_path: Path | None,
) -> tuple[list[dict[str, Any]], list[Path]]:
    if not isinstance(value, list) or len(value) != len(expected):
        gaps.append("criterion_case_coverage_missing")
        return [], []
    source_map = {row["path"]: row["sha256"] for row in source_rows}
    seen_criteria, results, evidence_paths = set(), [], []
    for criterion in value:
        if not isinstance(criterion, dict) or set(criterion) != {
            "criterion_id",
            "cases",
        }:
            gaps.append("criterion_case_record_malformed")
            continue
        criterion_id = criterion.get("criterion_id")
        cases = criterion.get("cases")
        if (
            not isinstance(criterion_id, str)
            or criterion_id not in expected
            or criterion_id in seen_criteria
        ):
            gaps.append("criterion_case_identity_invalid")
            continue
        seen_criteria.add(criterion_id)
        case_results = _daily_cases(
            cases,
            source_map,
            root,
            gaps,
            oracle_cache,
            mission,
            criterion_id,
            candidate_sha,
            mission_path,
        )
        criterion_definition = next(
            item
            for item in mission["completion_contract"]["criteria"]
            if item["id"] == criterion_id
        )
        result_row = {"criterion_id": criterion_id, "cases": case_results}
        if criterion_definition.get("verification_kind") == "deterministic_tool":
            gate_observation = _daily_native_gate_observation(
                criterion_definition,
                case_results,
                mission,
                candidate_sha,
                source_map,
                root,
                gaps,
            )
            if gate_observation is not None:
                result_row["native_gate_observation"] = gate_observation
        results.append(result_row)
        for case in case_results:
            evidence_paths.extend(case.pop("_evidence_paths", []))
    if seen_criteria != expected:
        gaps.append("criterion_case_coverage_missing")
    return results, evidence_paths


def _daily_native_gate_observation(
    criterion, cases, mission, candidate_sha, source_map, root, gaps
):
    gate = criterion["id"].partition(":")[2]
    if gate not in {"unit", "requirement-mutation", "receipt-trace"}:
        gaps.append("native_gate_unsupported:" + criterion["id"])
        return None
    sides = {case.get("polarity"): case for case in cases}
    if len(cases) != 2 or set(sides) != {"positive", "negative"}:
        gaps.append("native_gate_cases_incomplete:" + criterion["id"])
        return None
    positive, negative = sides["positive"], sides["negative"]
    if not _native_gate_cases_share_receipt(positive, negative):
        gaps.append("native_gate_receipt_mismatch:" + criterion["id"])
        return None
    path = Path(positive["execution_receipt_path"])
    try:
        receipt = _load_json(path, "factory.mission.local-mutation-capture.v1")
        facts = _native_gate_receipt_facts(
            receipt,
            positive,
            negative,
            criterion["id"],
            gate,
            mission,
            candidate_sha,
            source_map,
            root,
            gaps,
        )
    except (OSError, ProductMissionError, TypeError, ValueError, KeyError):
        facts = None
    if facts is None:
        gaps.append("native_gate_receipt_invalid:" + criterion["id"])
        return None
    return {
        "schema": "factory.daily-native-gate-observation.v1",
        "gate": gate,
        "status": "OBSERVED",
        "mission_id": mission["id"],
        "mission_sha256": mission["mission_sha256"],
        "criterion_id": criterion["id"],
        "candidate_sha256": candidate_sha,
        "source_manifest_sha256": receipt["source_manifest_sha256"],
        "evidence": facts,
        "claim_boundary": "Derived from current unsigned local pytest and mutation receipts; it proves selected local execution and receipt lineage under the writable-host trust assumption only.",
    }


def _native_gate_cases_share_receipt(positive, negative):
    fields = ("execution_receipt_path", "execution_receipt_sha256")
    return (
        all(positive.get(key) == negative.get(key) for key in fields)
        and positive.get("execution_evidence_kind") == "local_production_mutation"
        and negative.get("execution_evidence_kind") == "local_production_mutation"
        and positive.get("disposition") == "local_mutation_target_observed"
        and negative.get("disposition") == "local_mutation_control_observed"
    )


def _native_gate_receipt_facts(
    receipt,
    positive,
    negative,
    criterion_id,
    gate,
    mission,
    candidate_sha,
    source_map,
    root,
    gaps,
):
    expected = (
        receipt.get("status") == "OBSERVED"
        and receipt.get("authority") == "none"
        and receipt.get("mission_id") == mission["id"]
        and receipt.get("mission_sha256") == mission["mission_sha256"]
        and receipt.get("criterion_id") == criterion_id
        and receipt.get("candidate_sha256") == candidate_sha
        and receipt.get("target_case", {}).get("case_id") == positive["case_id"]
        and receipt.get("control_case", {}).get("case_id") == negative["case_id"]
    )
    if not expected:
        return None
    snapshot_ref = receipt.get("daily_contract_snapshot", {})
    snapshot_path = _daily_local_evidence_path(
        snapshot_ref.get("path"),
        snapshot_ref.get("sha256"),
        root,
        gaps,
        "native_gate_contract_snapshot",
    )
    capture_paths = _daily_local_capture_paths(receipt, root, gaps)
    if snapshot_path is None or not isinstance(capture_paths, list):
        return None
    target_path, control_path = capture_paths
    target, control = (
        _read_local_capture(target_path),
        _read_local_capture(control_path),
    )
    if receipt.get("source_manifest_sha256") != target.get(
        "source_manifest_sha256"
    ) or receipt.get("source_manifest_sha256") != control.get("source_manifest_sha256"):
        return None
    if not _native_gate_snapshot_matches(
        receipt,
        snapshot_path,
        positive,
        negative,
        mission,
        candidate_sha,
        source_map,
        root,
    ):
        return None
    if gate == "unit":
        observed = _native_gate_unit_observation(target)
    elif gate == "requirement-mutation":
        observed = _native_gate_mutation_observation(target, control)
    else:
        observed = _native_gate_trace_observation(
            receipt, target_path, control_path, target, control, root
        )
    if observed is None:
        return None
    return [
        {
            "role": "mission_case",
            "path": str(Path(positive["execution_receipt_path"]).resolve()),
            "sha256": positive["execution_receipt_sha256"],
        },
        {
            "role": "daily_contract_snapshot",
            "path": str(snapshot_path.resolve()),
            "sha256": snapshot_ref["sha256"],
        },
        *observed,
    ]


def _native_gate_snapshot_matches(
    receipt, path, positive, negative, mission, candidate_sha, source_map, root
):
    try:
        snapshot, observed_sources, digest = _local_capture_contract(
            _load_json(path, DAILY_VERIFICATION_SCHEMA), mission, root
        )
        criteria = {
            item["criterion_id"]: item["cases"] for item in snapshot["criteria"]
        }
        cases = {case["case_id"]: case for case in criteria[receipt["criterion_id"]]}
        before = receipt["daily_contract_sha256_before_capture"]
        return (
            _sha_path(path) == before
            and digest == candidate_sha
            and observed_sources == source_map
            and set(cases) == {positive["case_id"], negative["case_id"]}
            and all(
                cases[row["case_id"]]["polarity"] == row["polarity"]
                and cases[row["case_id"]]["input_paths"] == row["input_paths"]
                and cases[row["case_id"]]["input_sha256"] == row["input_sha256"]
                and cases[row["case_id"]]["observed_outcome"] == "unknown"
                and cases[row["case_id"]]["evidence"] == {}
                for row in (positive, negative)
            )
        )
    except (KeyError, OSError, ProductMissionError, TypeError, ValueError):
        return False


def _native_gate_unit_observation(target):
    observation = target.get("baseline_observation", {})
    selection = target.get("selection", {})
    reports = observation.get("reports")
    phases = (
        {row.get("phase"): row for row in reports if isinstance(row, dict)}
        if isinstance(reports, list)
        else {}
    )
    selector = selection.get("nodeid_selector")
    if (
        target.get("status") != "OBSERVED"
        or target.get("baseline", {}).get("process", {}).get("exit_code") != 0
        or observation.get("collected") != [selector]
        or observation.get("collection_incomplete") is not False
        or set(phases) != {"setup", "call", "teardown"}
        or any(
            row.get("outcome") != "passed" or row.get("xfail") is True
            for row in phases.values()
        )
    ):
        return None
    return [
        {
            "role": "unit_pytest_baseline",
            "path": selection["test_path"],
            "sha256": selection["test_sha256"],
            "selector": selector,
        }
    ]


def _native_gate_mutation_observation(target, control):
    target_mutant = target.get("mutant_observation", {})
    control_runs = (
        control.get("baseline_observation", {}),
        control.get("mutant_observation", {}),
    )
    reports = target_mutant.get("reports")
    failed = isinstance(reports, list) and any(
        isinstance(row, dict)
        and row.get("phase") == "call"
        and row.get("outcome") == "failed"
        and row.get("xfail") is False
        for row in reports
    )
    if not failed or any(
        not isinstance(run.get("reports"), list)
        or any(
            row.get("outcome") != "passed"
            for row in run["reports"]
            if isinstance(row, dict)
        )
        for run in control_runs
    ):
        return None
    mutation = target.get("production_mutation", {})
    if mutation.get("mutation_applied") is not True or mutation.get(
        "original_sha256"
    ) == mutation.get("mutant_sha256"):
        return None
    return [
        {
            "role": "target_mutant_pytest",
            "path": mutation["path"],
            "sha256": mutation["mutant_sha256"],
        }
    ]


def _native_gate_trace_observation(
    receipt, target_path, control_path, target, control, root
):
    refs = (receipt.get("target_capture", {}), receipt.get("control_capture", {}))
    actual = (target_path, control_path)
    if any(
        ref.get("path") != path.relative_to(Path(root).resolve()).as_posix()
        for ref, path in zip(refs, actual, strict=True)
    ):
        return None
    return [
        {"role": role, "path": str(path.resolve()), "sha256": ref["sha256"]}
        for role, path, ref in zip(
            ("target_capture", "control_capture"), actual, refs, strict=True
        )
    ]


def _daily_cases(
    value: Any,
    source_map: dict[str, str],
    root: Path,
    gaps: list[str],
    oracle_cache: dict[tuple[str, str, str, str], dict[str, Any] | None],
    mission: dict[str, Any],
    criterion_id: str,
    candidate_sha: str | None,
    mission_path: Path | None,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        gaps.append("required_positive_negative_cases_missing")
        return []
    if not 2 <= len(value) <= 8:
        gaps.append("required_positive_negative_cases_missing")
    results, ids, polarities = [], set(), set()
    for item in value:
        result, paths = _daily_case(
            item,
            source_map,
            root,
            gaps,
            oracle_cache,
            mission,
            criterion_id,
            candidate_sha,
            mission_path,
        )
        if result is None:
            continue
        case_id = result["case_id"]
        if case_id in ids:
            gaps.append("case_id_duplicate")
        ids.add(case_id)
        polarities.add(result["polarity"])
        result["_evidence_paths"] = paths
        results.append(result)
    if polarities != {"positive", "negative"}:
        gaps.append("required_positive_negative_cases_missing")
    return results


def _daily_case(
    item: Any,
    source_map: dict[str, str],
    root: Path,
    gaps: list[str],
    oracle_cache: dict[tuple[str, str, str, str], dict[str, Any] | None],
    mission: dict[str, Any],
    criterion_id: str,
    candidate_sha: str | None,
    mission_path: Path | None,
) -> tuple[dict[str, Any] | None, list[Path]]:
    fields = {
        "case_id",
        "polarity",
        "input_paths",
        "input_sha256",
        "expected_outcome",
        "observed_outcome",
        "evidence",
    }
    if not isinstance(item, dict) or set(item) != fields:
        gaps.append("case_record_malformed")
        return None, []
    case_id, polarity = item.get("case_id"), item.get("polarity")
    if (
        not isinstance(case_id, str)
        or not case_id.strip()
        or len(case_id) > 96
        or not isinstance(polarity, str)
        or polarity not in {"positive", "negative"}
    ):
        gaps.append("case_identity_invalid")
        return None, []
    input_paths = item.get("input_paths")
    if (
        not isinstance(input_paths, list)
        or not input_paths
        or any(not isinstance(path, str) for path in input_paths)
        or any(path not in source_map for path in input_paths)
        or len(set(input_paths)) != len(input_paths)
    ):
        gaps.append("case_input_unbound")
        input_rows = []
    else:
        input_rows = [
            {"path": path, "sha256": source_map[path]} for path in input_paths
        ]
    input_digest = _sha_bytes(_canonical(input_rows)) if input_rows else None
    if input_digest is None or item.get("input_sha256") != input_digest:
        gaps.append("case_input_digest_mismatch")
    expected = item.get("expected_outcome")
    claimed_observed = item.get("observed_outcome")
    evidence = item.get("evidence")
    oracle_evidence = isinstance(evidence, dict) and evidence.get("kind") == (
        "signed_test_oracle_v3"
    )
    local_evidence = isinstance(evidence, dict) and evidence.get("kind") == (
        "local_production_mutation"
    )
    allowed_outcomes = (
        {"baseline_assertion_pass_mutant_assertion_fail"}
        if oracle_evidence
        else {
            "baseline_assertion_pass_mutant_assertion_fail",
            "baseline_assertion_pass_mutant_assertion_pass",
        }
        if local_evidence
        else {"exit_zero", "exit_nonzero"}
    )
    if (
        not isinstance(expected, str)
        or expected not in allowed_outcomes
        or (
            not isinstance(claimed_observed, str)
            or claimed_observed not in allowed_outcomes | {"unknown"}
        )
    ):
        gaps.append("case_outcome_claim_malformed")
    if oracle_evidence:
        observed, paths = _daily_oracle_observation(
            evidence, item, source_map, root, gaps, oracle_cache
        )
        disposition = "signer_attested_baseline_and_mutant"
    elif local_evidence:
        observed, paths = _daily_local_mutation_observation(
            evidence,
            item,
            source_map,
            root,
            gaps,
            mission,
            criterion_id,
            candidate_sha,
            mission_path,
        )
        disposition = (
            "local_mutation_target_observed"
            if evidence.get("role") == "target"
            else "local_mutation_control_observed"
        )
    else:
        observed, path = _daily_e2e_observation(
            evidence, polarity, source_map, root, gaps
        )
        paths = [path] if path is not None else []
        disposition = "command_pair_observed"
    if observed is None or item.get("observed_outcome") != observed:
        gaps.append("case_observed_outcome_unverified")
    if expected != observed:
        gaps.append("case_expected_outcome_mismatch")
    return (
        {
            "case_id": case_id,
            "polarity": polarity,
            "input_paths": list(input_paths) if isinstance(input_paths, list) else [],
            "input_sha256": input_digest,
            "expected_outcome_claim": expected,
            "observed_outcome_claim": claimed_observed,
            "observed_outcome": observed,
            "execution_receipt_path": str(paths[0]) if paths else None,
            "execution_receipt_sha256": _sha_path(paths[0]) if paths else None,
            "execution_evidence_kind": evidence.get("kind")
            if isinstance(evidence, dict)
            else None,
            "trust_root_path": evidence.get("trust_root_path")
            if oracle_evidence
            else None,
            "trust_root_sha256": evidence.get("trust_root_sha256")
            if oracle_evidence
            else None,
            "environment_sha256": evidence.get("environment_sha256")
            if oracle_evidence
            else None,
            "oracle_case_id": evidence.get("oracle_case_id")
            if oracle_evidence
            else None,
            "oracle_test_path": evidence.get("test_path") if oracle_evidence else None,
            "oracle_test_line": evidence.get("test_line") if oracle_evidence else None,
            "oracle_test_symbol": evidence.get("test_symbol")
            if oracle_evidence
            else None,
            "application_output_observed": None
            if oracle_evidence or local_evidence
            else observed,
            "disposition": disposition
            if observed is not None and expected == observed
            else "unverified",
        },
        paths,
    )


def _daily_e2e_observation(
    evidence: Any,
    polarity: str,
    source_map: dict[str, str],
    root: Path,
    gaps: list[str],
) -> tuple[str | None, Path | None]:
    if (
        not isinstance(evidence, dict)
        or set(evidence) != {"kind", "path", "sha256", "result"}
        or evidence.get("kind") != "e2e_command_pair"
    ):
        gaps.append("execution_evidence_unsupported")
        return None, None
    receipt, path = _daily_e2e_receipt(evidence, root, gaps)
    if receipt is None:
        return None, path
    _daily_e2e_artifacts(receipt, source_map, root, gaps)
    if evidence.get("result") != polarity:
        gaps.append("execution_result_side_mismatch")
        return None, path
    return _daily_e2e_command_outcome(receipt, polarity, gaps), path


def _daily_local_mutation_observation(
    evidence,
    case,
    source_map,
    root,
    gaps,
    mission,
    criterion_id,
    candidate_sha,
    mission_path,
):
    fields = {"kind", "path", "sha256", "role"}
    if not isinstance(evidence, dict) or set(evidence) != fields:
        gaps.append("execution_evidence_unsupported")
        return None, []
    path = _daily_local_evidence_path(
        evidence.get("path"),
        evidence.get("sha256"),
        root,
        gaps,
        "local_mutation_receipt",
    )
    if path is None:
        return None, []
    try:
        receipt = _load_json(path, "factory.mission.local-mutation-capture.v1")
        target_path, control_path = _daily_local_capture_paths(receipt, root, gaps)
        target, control = (
            _read_local_capture(target_path),
            _read_local_capture(control_path),
        )
        _verify_local_capture_pair(
            receipt,
            target,
            control,
            case,
            source_map,
            candidate_sha,
            mission,
            criterion_id,
            mission_path,
            root,
            gaps,
        )
        snapshot_path = _daily_capture_contract_snapshot(
            receipt, case, criterion_id, mission, source_map, candidate_sha, root, gaps
        )
        if snapshot_path is None:
            raise ValueError("pre-capture case contract is missing or stale")
        binding = (
            receipt["target_case"]
            if evidence["role"] == "target"
            else receipt["control_case"]
        )
        capture_path = target_path if evidence["role"] == "target" else control_path
        expected_role = "positive" if evidence["role"] == "target" else "negative"
        if (
            evidence["role"] not in {"target", "control"}
            or binding["case_id"] != case["case_id"]
            or binding["polarity"] != expected_role
            or binding["input_paths"] != case["input_paths"]
            or binding["input_sha256"] != case["input_sha256"]
            or binding["evidence_sha256"] != _sha_path(capture_path)
        ):
            raise ValueError("capture case binding mismatch")
        outcome = binding["expected_outcome"]
        paths = [path, target_path, control_path]
        for capture_path, capture in ((target_path, target), (control_path, control)):
            diff_path = (
                capture_path.parent / capture["production_mutation"]["diff_path"]
            )
            if (
                not _valid_sha256(capture["production_mutation"].get("diff_sha256"))
                or _sha_path(diff_path) != capture["production_mutation"]["diff_sha256"]
            ):
                raise ValueError("capture diff is stale")
            paths.append(diff_path)
        paths.append(snapshot_path)
        return outcome, paths
    except (KeyError, OSError, ProductMissionError, TypeError, ValueError):
        gaps.append("execution_local_capture_invalid_or_stale")
        return None, [path]


def _daily_capture_contract_snapshot(
    receipt, case, criterion_id, mission, source_map, candidate_sha, root, gaps
):
    reference = receipt.get("daily_contract_snapshot", {})
    path = _daily_local_evidence_path(
        reference.get("path"),
        reference.get("sha256"),
        root,
        gaps,
        "local_capture_contract_snapshot",
    )
    if path is None or reference.get("sha256") != receipt.get(
        "daily_contract_sha256_before_capture"
    ):
        return None
    try:
        snapshot, observed_sources, observed_candidate = _local_capture_contract(
            _load_json(path, DAILY_VERIFICATION_SCHEMA), mission, root
        )
        criteria = {
            item["criterion_id"]: item["cases"] for item in snapshot["criteria"]
        }
        saved_case = next(
            row for row in criteria[criterion_id] if row["case_id"] == case["case_id"]
        )
        return (
            path
            if (
                observed_sources == source_map
                and observed_candidate == candidate_sha
                and saved_case["polarity"] == case["polarity"]
                and saved_case["input_paths"] == case["input_paths"]
                and saved_case["input_sha256"] == case["input_sha256"]
                and saved_case["observed_outcome"] == "unknown"
                and saved_case["evidence"] == {}
            )
            else None
        )
    except (
        KeyError,
        OSError,
        ProductMissionError,
        StopIteration,
        TypeError,
        ValueError,
    ):
        return None


def _daily_local_capture_paths(receipt, root, gaps):
    paths = []
    for key in ("target_capture", "control_capture"):
        binding = receipt.get(key)
        if not isinstance(binding, dict) or set(binding) != {"path", "sha256"}:
            gaps.append("execution_local_capture_binding_malformed")
            return None, None
        path = _daily_local_evidence_path(
            binding.get("path"),
            binding.get("sha256"),
            root,
            gaps,
            "local_mutation_capture",
        )
        if path is None:
            return None, None
        paths.append(path)
    return paths


def _verify_local_capture_pair(
    receipt,
    target,
    control,
    case,
    source_map,
    candidate_sha,
    mission,
    criterion_id,
    mission_path,
    root,
    gaps,
):
    from .runtime_audit_runner import project_local_production_mutation_v3_candidate

    mission_file = Path(mission_path).resolve() if mission_path else None
    mission_file_sha = (
        _sha_path(mission_file) if mission_file and mission_file.is_file() else None
    )
    mission_bound_path = receipt.get("mission_path")
    mission_bound_file = _local_receipt_mission_path(mission_bound_path, root)
    mission_bound_file_sha = (
        _sha_path(mission_bound_file) if mission_bound_file else None
    )
    budget = receipt.get("execution_budget")
    if not all(
        (
            receipt.get("status") == "OBSERVED",
            receipt.get("authority") == "none",
            receipt.get("local_execution_observed") is True,
            receipt.get("mission_id") == mission.get("id"),
            receipt.get("mission_sha256") == mission.get("mission_sha256"),
            receipt.get("mission_file_sha256") == mission_file_sha,
            receipt.get("mission_file_sha256") == mission_bound_file_sha,
            mission_bound_file == mission_file,
            receipt.get("criterion_id") == criterion_id,
            receipt.get("candidate_sha256") == candidate_sha,
            receipt.get("captures_same_candidate_and_mutation") is True,
            receipt.get("claim_boundary", "").startswith(
                "Explicit operator-invoked local process observation"
            ),
            _local_capture_budget_valid(budget),
        )
    ):
        raise ValueError("local observation identity or trust boundary mismatch")
    source_manifest = _candidate_manifest_for_local_capture(target)
    if source_manifest != _candidate_manifest_for_local_capture(control):
        raise ValueError("target and control source manifests differ")
    if any(source_manifest.get(path) != digest for path, digest in source_map.items()):
        raise ValueError("capture source manifest differs from candidate inputs")
    target_projection = project_local_production_mutation_v3_candidate(target)
    if target_projection.get("status") != "CANDIDATE":
        raise ValueError("target natural assertion is not observed")
    if not _validate_unaffected_control_capture(control, target, root):
        raise ValueError("unaffected control did not pass under the candidate mutation")
    if not all(
        _local_capture_current_source(item, root, source_manifest)
        for item in (target, control)
    ):
        raise ValueError(
            "capture no longer matches current source and runtime configuration"
        )
    mutation = target.get("production_mutation", {})
    selection = target.get("selection", {})
    if (
        selection.get("test_path") not in case.get("input_paths", [])
        or mutation.get("path") not in case.get("input_paths", [])
        or mutation.get("path") not in source_map
        or source_manifest.get(mutation.get("path")) != mutation.get("original_sha256")
    ):
        raise ValueError("target test or production source is not bound to this case")
    if receipt.get("source_manifest_sha256") != target.get("source_manifest_sha256"):
        raise ValueError("receipt source manifest binding differs")


def _local_receipt_mission_path(value, root):
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        return None
    try:
        workspace = Path(root).resolve()
        candidate = (workspace / value).resolve(strict=True)
        candidate.relative_to(workspace)
        return candidate if candidate.is_file() else None
    except (OSError, RuntimeError, ValueError):
        return None


def _local_capture_budget_valid(value):
    if not isinstance(value, dict) or set(value) != {
        "overall_timeout_seconds",
        "target_child_timeout_seconds",
        "control_child_timeout_seconds",
        "maximum_child_processes",
    }:
        return False
    overall = value.get("overall_timeout_seconds")
    target, control = (
        value.get("target_child_timeout_seconds"),
        value.get("control_child_timeout_seconds"),
    )
    return (
        all(type(item) is int for item in (overall, target, control))
        and 1 <= target <= 300
        and 1 <= control <= 300
        and max(target, control) <= overall <= 1200
        and value.get("maximum_child_processes") == 4
    )


def _candidate_manifest_for_local_capture(capture):
    from .runtime_audit_runner import _candidate_manifest

    return _candidate_manifest(capture)


def _daily_oracle_observation(
    evidence: Any,
    case: dict[str, Any],
    source_map: dict[str, str],
    root: Path,
    gaps: list[str],
    cache: dict[tuple[str, str, str, str], dict[str, Any] | None],
) -> tuple[str | None, list[Path]]:
    fields = {
        "kind",
        "path",
        "sha256",
        "trust_root_path",
        "trust_root_sha256",
        "environment_sha256",
        "test_path",
        "test_line",
        "test_symbol",
        "oracle_case_id",
    }
    if not isinstance(evidence, dict) or set(evidence) != fields:
        gaps.append("execution_evidence_unsupported")
        return None, []
    receipt_path = _daily_local_evidence_path(
        evidence.get("path"), evidence.get("sha256"), root, gaps, "oracle_receipt"
    )
    trust_path = _daily_local_evidence_path(
        evidence.get("trust_root_path"),
        evidence.get("trust_root_sha256"),
        root,
        gaps,
        "oracle_trust_root",
    )
    if receipt_path is None or trust_path is None:
        return None, [path for path in (receipt_path, trust_path) if path is not None]
    environment_sha = evidence.get("environment_sha256")
    if not _valid_sha256(environment_sha):
        gaps.append("execution_environment_pin_invalid")
        return None, [receipt_path, trust_path]
    source_rows = [
        {"path": path, "sha256": digest} for path, digest in sorted(source_map.items())
    ]
    source_sha = _sha_bytes(_canonical(source_rows))
    cache_key = (
        str(receipt_path),
        str(trust_path),
        evidence["trust_root_sha256"],
        environment_sha,
    )
    if cache_key not in cache:
        try:
            from .runtime_attestation import (
                TEST_ORACLE_VERIFICATION_SCHEMA_V3,
                verify_signed_test_oracles,
            )

            verified = verify_signed_test_oracles(
                receipt_path,
                trust_path,
                trust_root_sha256=evidence["trust_root_sha256"],
                source_manifest_sha256=source_sha,
                environment_sha256=environment_sha,
            )
            cache[cache_key] = (
                verified
                if verified.get("schema") == TEST_ORACLE_VERIFICATION_SCHEMA_V3
                and verified.get("source_manifest_sha256") == source_sha
                and verified.get("environment_sha256") == environment_sha
                else None
            )
            if cache[cache_key] is None:
                gaps.append("execution_oracle_v3_required")
        except (OSError, TypeError, ValueError, KeyError, RuntimeError):
            cache[cache_key] = None
            gaps.append("execution_oracle_invalid_or_stale")
    verified = cache[cache_key]
    if verified is None:
        if "execution_oracle_invalid_or_stale" not in gaps:
            gaps.append("execution_oracle_invalid_or_stale")
        return None, [receipt_path, trust_path]
    row = _daily_oracle_case_row(evidence, verified, case, source_map, gaps)
    if row is None:
        return None, [receipt_path, trust_path]
    return "baseline_assertion_pass_mutant_assertion_fail", [
        receipt_path,
        trust_path,
    ]


def _daily_local_evidence_path(
    value: Any,
    digest: Any,
    root: Path,
    gaps: list[str],
    label: str,
) -> Path | None:
    if not isinstance(value, str) or not value.strip() or not _valid_sha256(digest):
        gaps.append(label + "_missing_or_malformed")
        return None
    supplied = Path(value)
    candidate = supplied if supplied.is_absolute() else Path(root).resolve() / supplied
    try:
        path = candidate.resolve()
        path.relative_to(Path(root).resolve())
        if not path.is_file() or path.stat().st_size > MAX_DAILY_RECEIPT_BYTES:
            raise ValueError("evidence is missing or oversized")
        if _sha_path(path) != digest:
            raise ValueError("evidence digest is stale")
    except (OSError, RuntimeError, ValueError):
        gaps.append(label + "_invalid_or_stale")
        return None
    return path


def _daily_oracle_case_row(
    evidence: dict[str, Any],
    verified: dict[str, Any],
    case: dict[str, Any],
    source_map: dict[str, str],
    gaps: list[str],
) -> dict[str, Any] | None:
    test_path = evidence.get("test_path")
    line = evidence.get("test_line")
    symbol = evidence.get("test_symbol")
    oracle_case_id = evidence.get("oracle_case_id")
    rows = [
        row
        for row in verified.get("tests", [])
        if isinstance(row, dict)
        and (row.get("path"), row.get("line"), row.get("symbol"))
        == (test_path, line, symbol)
    ]
    if (
        not isinstance(test_path, str)
        or type(line) is not int
        or not isinstance(evidence.get("test_symbol"), str)
        or not isinstance(oracle_case_id, str)
        or len(rows) != 1
    ):
        gaps.append("execution_oracle_test_identity_unmatched")
        return None
    row = rows[0]
    baseline, mutation = row.get("baseline"), row.get("mutation")
    if not isinstance(baseline, dict) or not isinstance(mutation, dict):
        gaps.append("execution_oracle_case_missing")
        return None
    catalogs = [baseline.get("collection_catalog"), mutation.get("collection_catalog")]
    source_paths = _daily_oracle_catalog_sources(catalogs, source_map)
    if source_paths is None or not _daily_oracle_run_matches(
        row, baseline, mutation, test_path, oracle_case_id, source_map, catalogs
    ):
        gaps.append("execution_oracle_sources_or_case_unbound")
        return None
    source_paths.update({test_path, mutation.get("source_path")})
    input_paths = case.get("input_paths")
    if not isinstance(input_paths, list) or not source_paths <= set(input_paths):
        gaps.append("execution_oracle_inputs_not_bound_to_case")
        return None
    return row


def _daily_oracle_run_matches(
    row, baseline, mutation, test_path, case_id, source_map, catalogs
):
    return (
        baseline.get("status") == "PASS"
        and mutation.get("status") == "FAIL"
        and baseline.get("phase") == "call"
        and mutation.get("phase") == "call"
        and baseline.get("setup_status") == "PASS"
        and mutation.get("setup_status") == "PASS"
        and baseline.get("teardown_status") == "PASS"
        and mutation.get("teardown_status") == "PASS"
        and source_map.get(test_path) == row.get("test_sha256")
        and source_map.get(mutation.get("source_path")) == mutation.get("source_sha256")
        and case_id in baseline.get("case_ids", [])
        and case_id in mutation.get("case_ids", [])
        and mutation.get("failure_kind") == "assertion"
        and all(isinstance(item, dict) for item in catalogs)
        and _daily_oracle_assertions_match(baseline, mutation, case_id)
    )


def _daily_oracle_catalog_sources(catalogs, source_map):
    source_paths = set()
    for catalog in catalogs:
        if not isinstance(catalog, dict):
            return None
        config = catalog.get("config_manifest")
        if not isinstance(config, list):
            return None
        if catalog.get("config_identity") != (
            "manifest" if config else "pytest-default"
        ):
            return None
        for item in config:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                return None
            path, digest = item["path"], item.get("sha256")
            if source_map.get(path) != digest:
                return None
            source_paths.add(path)
    return source_paths


def _daily_oracle_assertions_match(
    baseline: dict[str, Any], mutation: dict[str, Any], case_id: str
) -> bool:
    baseline_rows = baseline.get("assertion_observations")
    mutation_rows = mutation.get("assertion_observations")
    return (
        isinstance(baseline_rows, list)
        and isinstance(mutation_rows, list)
        and any(
            isinstance(row, dict)
            and row.get("case_id") == case_id
            and row.get("outcome") == "PASS"
            and row.get("failure_visible") is False
            for row in baseline_rows
        )
        and any(
            isinstance(row, dict)
            and row.get("case_id") == case_id
            and row.get("outcome") == "FAIL"
            and row.get("failure_visible") is True
            for row in mutation_rows
        )
    )


def _daily_e2e_receipt(
    evidence: dict[str, Any], root: Path, gaps: list[str]
) -> tuple[dict[str, Any] | None, Path | None]:
    path_text = evidence.get("path")
    if not isinstance(path_text, str) or not path_text.strip():
        gaps.append("execution_evidence_path_missing")
        return None, None
    path = Path(path_text)
    path = path if path.is_absolute() else Path(root).resolve() / path
    try:
        path = path.resolve()
        path.relative_to(Path(root).resolve())
    except (OSError, RuntimeError, ValueError):
        gaps.append("execution_evidence_outside_root")
        return None, None
    if not path.is_file() or not _valid_sha256(evidence.get("sha256")):
        gaps.append("execution_evidence_missing_or_malformed")
        return None, None
    if path.stat().st_size > MAX_DAILY_RECEIPT_BYTES:
        gaps.append("execution_evidence_size_limit")
        return None, path
    if _sha_path(path) != evidence["sha256"]:
        gaps.append("execution_evidence_stale")
        return None, None
    try:
        from .e2e_proof import validate_e2e_proof_receipt

        receipt = validate_e2e_proof_receipt(_load_json(path))
    except (ValueError, KeyError, TypeError, OSError, RuntimeError):
        gaps.append("execution_evidence_invalid")
        return None, None
    return receipt, path


def _daily_e2e_command_outcome(
    receipt: dict[str, Any], polarity: str, gaps: list[str]
) -> str | None:
    commands = receipt.get("commands")
    command = commands.get(polarity) if isinstance(commands, dict) else None
    if not isinstance(command, dict) or command.get("status") != "completed":
        gaps.append("execution_infrastructure_failure")
        return None
    exit_code = command.get("exit_code")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        gaps.append("execution_infrastructure_failure")
        return None
    if receipt.get("ok") is not True or receipt.get("run_state") != "proof_pass":
        gaps.append("execution_receipt_not_green")
        return None
    return "exit_zero" if exit_code == 0 else "exit_nonzero"


def _daily_e2e_artifacts(
    receipt: dict[str, Any],
    source_map: dict[str, str],
    root: Path,
    gaps: list[str],
) -> None:
    for artifact in receipt.get("artifacts", []):
        if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
            gaps.append("execution_artifact_manifest_malformed")
            continue
        try:
            artifact_path = (Path(root).resolve() / artifact["path"]).resolve()
            artifact_path.relative_to(Path(root).resolve())
        except (OSError, RuntimeError, ValueError):
            gaps.append("execution_artifact_outside_root")
            continue
        if (
            not artifact_path.is_file()
            or not _valid_sha256(artifact.get("sha256"))
            or artifact_path.stat().st_size > MAX_DAILY_SOURCE_BYTES
            or _sha_path(artifact_path) != artifact["sha256"]
        ):
            gaps.append("execution_artifact_stale")
    source_artifacts = {
        artifact.get("path"): artifact.get("sha256")
        for artifact in receipt.get("artifacts", [])
        if isinstance(artifact, dict) and isinstance(artifact.get("path"), str)
    }
    if any(
        source_artifacts.get(source) != digest for source, digest in source_map.items()
    ):
        gaps.append("execution_candidate_source_binding_missing")


def _completion_result_list(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    results = manifest.get("criteria")
    if (
        not isinstance(results, list)
        or not 1 <= len(results) <= MAX_COMPLETION_CRITERIA
    ):
        raise ProductMissionError(
            "NO_FINISH_CONTRACT",
            f"validation must contain 1-{MAX_COMPLETION_CRITERIA} criteria",
        )
    return results


def _validate_completion_coverage(
    results: list[dict[str, Any]], expected: list[str]
) -> None:
    ids = [item.get("id") for item in results if isinstance(item, dict)]
    if (
        len(ids) != len(results)
        or len(ids) != len(set(ids))
        or sorted(ids) != sorted(expected)
    ):
        raise ProductMissionError(
            "NO_FINISH_CONTRACT",
            "validation must cover every completion criterion exactly once",
        )


def _validated_completion_item(
    item: dict[str, Any],
    criterion: dict[str, Any],
    mission: dict[str, Any],
    manifest: dict[str, Any],
    root: Path,
) -> tuple[dict[str, Any], list[Path]]:
    evidence_paths: list[Path] = []
    paths = item.get("evidence")
    if (
        item.get("passed") is not True
        or not isinstance(paths, list)
        or not paths
        or not all(isinstance(value, str) and value.strip() for value in paths)
    ):
        raise ProductMissionError(
            "NO_FINISH_CONTRACT",
            f"criterion {item.get('id')} must pass with evidence",
        )
    resolved = [
        Path(value) if Path(value).is_absolute() else Path(root).resolve() / value
        for value in paths
    ]
    browser_summary = None
    if criterion.get("verification_kind") == "browser_control":
        if len(resolved) != 1:
            raise ProductMissionError(
                "BROWSER_FLOW_INVALID",
                "browser-control criteria require exactly one structured evidence receipt",
            )
        verifier_id = manifest["verifier_id"].strip()
        artifacts, browser_summary = _browser_flow_artifacts(
            mission, criterion, resolved[0], verifier_id, root
        )
        evidence_paths.extend(artifacts)
    evidence_paths.extend(resolved)
    normalized_item = {
        "id": item["id"],
        "passed": True,
        "evidence": [str(path.resolve()) for path in resolved],
    }
    if browser_summary is not None:
        normalized_item["browser_flow"] = browser_summary
    return normalized_item, evidence_paths


def close_mission(
    mission_path: Path, validation_path: Path, root: Path, *, force: bool = False
) -> dict[str, Any]:
    """Write completion only after fresh-context, exact-coverage verification."""
    mission_check = verify_mission(mission_path)
    if not mission_check["valid"]:
        raise ProductMissionError(
            "MISSION_INPUT_DRIFT", "; ".join(mission_check["errors"])
        )
    mission = _load_mission(mission_path)
    manifest, resolved_validation = _validation_manifest(validation_path, root)
    _validate_context_wall(mission, manifest)
    results, evidence = _validated_completion_results(mission, manifest, root)
    daily_verification, daily_evidence = _daily_verification_summary(
        manifest.get("daily_verification", _DAILY_VERIFICATION_UNSET),
        mission,
        root,
        mission_path=Path(mission_path),
    )
    evidence_paths = [Path(item["path"]) for item in evidence] + daily_evidence
    evidence = _evidence(Path(root), list(dict.fromkeys(evidence_paths)))
    if len(evidence) > MAX_COMPLETION_EVIDENCE:
        raise ProductMissionError(
            "NO_FINISH_CONTRACT",
            f"completion evidence is limited to {MAX_COMPLETION_EVIDENCE} files",
        )
    daily_contract_present = "daily_verification" in manifest
    if daily_verification.get("complete") is True and not _daily_evidence_is_bound(
        daily_verification, evidence, root
    ):
        raise ProductMissionError(
            "DAILY_VERIFICATION_DRIFT",
            "daily verification evidence changed while completion was being sealed",
        )
    core = {
        "schema": MISSION_COMPLETION_SCHEMA,
        "mission": {
            "path": str(Path(mission_path).resolve()),
            "sha256": _sha_path(mission_path),
            "mission_sha256": mission["mission_sha256"],
        },
        "validation": {
            "path": str(resolved_validation),
            "sha256": _sha_path(resolved_validation),
        },
        "creator_id": manifest["creator_id"].strip(),
        "verifier_id": manifest["verifier_id"].strip(),
        "verifier_context": manifest["verifier_context"],
        "adapter_attestation": manifest.get("adapter_attestation"),
        "criteria": results,
        "evidence": evidence,
        "status": "completed"
        if not daily_contract_present or daily_verification.get("complete") is True
        else "incomplete",
        "daily_verification": daily_verification,
        "authority": {"merge": False, "publish": False, "deploy": False},
        "markers": [
            "CREATOR_VERIFIER_CONTEXT_WALL",
            "VERIFIER_IDENTITY_DISTINCT",
            "VERIFIER_ADAPTER_ATTESTED",
            "NO_FINISH_CONTRACT",
            "VALIDATION_EVIDENCE_BOUND",
        ],
    }
    receipt = {
        **core,
        "completion_sha256": _sha_bytes(_canonical(core)),
        "generated_at": _now(),
    }
    path = Path(mission_path).resolve().parent / "completion.json"
    _atomic_json(path, receipt, force=force)
    return {**receipt, "path": str(path)}


def _daily_evidence_is_bound(
    summary: dict[str, Any], evidence: list[dict[str, Any]], root: Path
) -> bool:
    actual = {item["path"]: item["sha256"] for item in evidence}
    expected: dict[str, str] = {}
    for source in summary.get("source_manifest", []):
        expected[str((Path(root).resolve() / source["path"]).resolve())] = source[
            "sha256"
        ]
    for criterion in summary.get("criteria", []):
        for case in criterion.get("cases", []):
            receipt_path, receipt_sha = (
                case.get("execution_receipt_path"),
                case.get("execution_receipt_sha256"),
            )
            if isinstance(receipt_path, str) and isinstance(receipt_sha, str):
                expected[str(Path(receipt_path).resolve())] = receipt_sha
            trust_path, trust_sha = (
                case.get("trust_root_path"),
                case.get("trust_root_sha256"),
            )
            if isinstance(trust_path, str) and isinstance(trust_sha, str):
                path = Path(trust_path)
                path = path if path.is_absolute() else Path(root).resolve() / path
                expected[str(path.resolve())] = trust_sha
    if not expected:
        return False
    return all(
        _daily_digest_is_current(path, digest, actual)
        for path, digest in expected.items()
    )


def _daily_digest_is_current(path: str, digest: str, evidence: dict[str, str]) -> bool:
    if evidence.get(path) != digest:
        return False
    try:
        return _sha_path(Path(path)) == digest
    except OSError:
        return False


def _bound_file_error(item: dict[str, Any], label: str) -> str | None:
    path = Path(item["path"])
    if not path.exists() or _sha_path(path) != item["sha256"]:
        return (
            f"{label} drift: {path}" if label == "evidence" else f"{label} input drift"
        )
    return None


def _completion_errors(receipt: dict[str, Any]) -> list[str]:
    core = {
        key: value
        for key, value in receipt.items()
        if key not in {"completion_sha256", "generated_at", "path"}
    }
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
    summary = receipt.get("daily_verification")
    if (
        receipt.get("status") == "completed"
        and isinstance(summary, dict)
        and summary.get("schema") == DAILY_VERIFICATION_SCHEMA
        and summary.get("status") != "LEGACY_CLAIMED"
    ):
        try:
            mission = _load_mission(mission_path)
            graph_path = Path(mission["inputs"]["graph_path"]).resolve()
            workspace = graph_path.parents[3]
            validation_path = Path(receipt["validation"]["path"])
            manifest, resolved_validation = _validation_manifest(
                validation_path, workspace
            )
            if _sha_path(resolved_validation) != receipt["validation"]["sha256"]:
                raise ProductMissionError(
                    "VALIDATION_DRIFT", "validation input changed during verification"
                )
            if "daily_verification" not in manifest:
                raise ProductMissionError(
                    "DAILY_VERIFICATION_DRIFT",
                    "completed daily receipt has no daily verification contract",
                )
            current_summary, _ = _daily_verification_summary(
                manifest["daily_verification"],
                mission,
                workspace,
                mission_path=mission_path,
            )
            if _canonical(current_summary) != _canonical(summary):
                raise ProductMissionError(
                    "DAILY_VERIFICATION_DRIFT",
                    "daily verification summary no longer matches its validation contract",
                )
            if not _daily_evidence_is_bound(
                current_summary, receipt.get("evidence", []), workspace
            ):
                raise ProductMissionError(
                    "DAILY_VERIFICATION_DRIFT",
                    "daily verification evidence no longer matches current source bindings",
                )
        except (KeyError, IndexError, OSError, ProductMissionError, TypeError) as exc:
            errors.append(f"daily verification no longer verifies: {exc}")
    return errors


def verify_mission_completion(completion_path: Path) -> dict[str, Any]:
    """Verify completion, validation, mission, and every evidence file hash."""
    receipt = _load_json(completion_path, MISSION_COMPLETION_SCHEMA)
    errors = _completion_errors(receipt)
    summary = receipt.get("daily_verification")
    if not isinstance(summary, dict):
        summary = _daily_verification_incomplete("legacy_completion_receipt")
        summary["status"] = "LEGACY_CLAIMED"
    integrity_valid = not errors
    complete = (
        integrity_valid
        and receipt.get("status") == "completed"
        and summary.get("status") == "COMPLETE"
    )
    legacy_claimed = summary.get("status") == "LEGACY_CLAIMED"
    completion_valid = integrity_valid and (complete or legacy_claimed)
    if integrity_valid and not (complete or legacy_claimed):
        errors.append(
            "completion remains incomplete: "
            + ", ".join(summary.get("gaps", ["daily verification incomplete"]))
        )
    marker = (
        "MISSION_COMPLETION_VERIFIED"
        if complete
        else "MISSION_COMPLETION_INCOMPLETE"
        if integrity_valid
        else "MISSION_COMPLETION_DRIFT"
    )
    result = {
        "schema": "factory.mission.completion.verification.v1",
        "valid": completion_valid,
        "integrity_valid": integrity_valid,
        "complete": complete,
        "status": "verified"
        if complete
        else "legacy_claimed"
        if legacy_claimed
        else "incomplete"
        if integrity_valid
        else "invalid",
        "marker": marker,
        "daily_verification": summary,
        "errors": errors,
        "authority": "completion verification only; no merge or deployment authority",
    }
    if errors:
        result["failure"] = explain_failure(
            "MISSION_COMPLETION_DRIFT", "; ".join(errors), errors=errors
        )
    return result


def mission_completion_graph_projection(
    verification: dict[str, Any] | None,
) -> dict[str, Any]:
    """Project integrity and completion separately for read-only graph consumers."""
    integrity_valid = (
        verification is not None and verification.get("integrity_valid") is True
    )
    complete = (
        integrity_valid
        and verification.get("valid") is True
        and verification.get("complete") is True
    )
    return {
        "status": "verified"
        if complete
        else "incomplete"
        if integrity_valid
        else "invalid",
        "integrity_valid": integrity_valid,
        "complete": complete,
        "errors": verification.get("errors", []) if verification else [],
    }


def _pr_markdown(draft: dict[str, Any]) -> str:
    requirements = "\n".join(f"- [ ] `{item}`" for item in draft["requirements"])
    evidence = (
        "\n".join(
            f"- `{item['path']}` sha256 `{item['sha256']}`"
            for item in draft["evidence"]
        )
        or "- No evidence attached yet."
    )
    risks = "\n".join(f"- {item}" for item in draft["risks"])
    unknowns = "\n".join(f"- {item}" for item in draft["unproven_claims"])
    changes = "\n".join(
        f"- {item}"
        for item in draft["architecture_changes"] + draft["data_contract_changes"]
    )
    proof = "\n".join(
        f"- {name}: {len(items)} attached"
        for name, items in draft["review_evidence"].items()
    )
    return f"""# {draft["title"]}

## User value

{draft["user_outcome"]}

- Before: {draft["before_after"]["before"]}
- After: {draft["before_after"]["after"]}

## Requirement coverage

{requirements}

## Evidence

{evidence}

## Architecture and data contracts

{changes}

## Review proof inventory

{proof}

## Budget and trace

- Budget: {draft["budget_consumption"]["status"]}
- Trace links: {len(draft["trace_links"])}

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


def draft_pr(
    mission_path: Path,
    root: Path,
    evidence_paths: list[Path] | None = None,
    force: bool = False,
) -> dict:
    """Create a reviewer-ready, evidence-linked draft without remote side effects."""
    verification = verify_mission(mission_path)
    if not verification["valid"]:
        raise ProductMissionError(
            "MISSION_INPUT_DRIFT", "; ".join(verification["errors"])
        )
    mission = _load_mission(mission_path)
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
            "changed": [],
            "deferred": [],
            "rejected": [],
            "invalidated": [],
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
            "status": "unreported"
            if not evidence
            else "evidence_attached_usage_not_inferred",
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
        "outcome_events": graph.get("success_events")
        or ["prd_declared_metric_missing"],
        "unproven_claims": (
            [f"UX state not declared in PRD: {state}" for state in missing_states]
            + (["No implementation evidence attached."] if not evidence else [])
            + [
                f"No {name} evidence attached."
                for name, items in review_evidence.items()
                if not items
            ]
        ),
        "authority": {
            "draft_only": True,
            "merge": False,
            "release": False,
            "publish": False,
            "deploy": False,
        },
        "markers": [
            "PR_EVIDENCE_LINKED",
            "PR_DRAFT_NO_MERGE_AUTHORITY",
            "PR_REVIEW_PACKAGE_COMPLETE",
            "PR_UNPROVEN_CLAIMS_EXPLICIT",
        ],
    }
    draft = {
        **core,
        "draft_sha256": _sha_bytes(_canonical(core)),
        "generated_at": _now(),
    }
    directory = Path(root).resolve() / ".factory" / "missions" / mission["id"]
    json_path = directory / "pr_draft.json"
    md_path = directory / "PR_DRAFT.md"
    markdown = _pr_markdown(draft)
    if not force:
        for path, content in (
            (json_path, json.dumps(draft, indent=2, sort_keys=True) + "\n"),
            (md_path, markdown),
        ):
            if path.exists() and path.read_text(encoding="utf-8") != content:
                raise ProductMissionError(
                    "OUTPUT_EXISTS", f"refusing to replace existing output: {path}"
                )
    _atomic_json(json_path, draft, force=force)
    _atomic_text(md_path, markdown, force=force)
    return {**draft, "path": str(json_path), "markdown": str(md_path)}


def _validate_outcome(
    metric: str,
    value: float | None,
    target: float | None,
    evidence_class: str,
    source: str | None,
    notes: str,
) -> None:
    _validate_outcome_metadata(metric, evidence_class, source, notes)
    for name, selected in (("VALUE", value), ("TARGET", target)):
        _validate_outcome_number(name, selected)


def _validate_outcome_metadata(
    metric: str, evidence_class: str, source: str | None, notes: str
) -> None:
    if evidence_class not in EVIDENCE_CLASSES:
        raise ProductMissionError(
            "EVIDENCE_CLASS_INVALID",
            f"evidence class must be one of {', '.join(sorted(EVIDENCE_CLASSES))}",
        )
    if not metric.strip() or len(metric) > 120:
        raise ProductMissionError("METRIC_INVALID", "metric must be 1-120 characters")
    if len(notes) > MAX_NOTES:
        raise ProductMissionError(
            "OUTCOME_NOTES_LIMIT", f"notes must be at most {MAX_NOTES} characters"
        )
    if evidence_class == "measured" and not (source and source.strip()):
        raise ProductMissionError(
            "MEASURED_SOURCE_REQUIRED", "measured outcomes require a source"
        )


def _validate_outcome_number(name: str, selected: float | None) -> None:
    if selected is not None and (
        isinstance(selected, bool)
        or not isinstance(selected, (int, float))
        or not math.isfinite(selected)
    ):
        raise ProductMissionError(
            f"OUTCOME_{name}_INVALID", f"{name.lower()} must be numeric or null"
        )


def _last_outcome_sha(path: Path) -> str | None:
    if not path.exists():
        return None
    lines = [
        line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    return json.loads(lines[-1]).get("record_sha256") if lines else None


def _outcome_verdict(value: float | None, target: float | None) -> str:
    if value is None or target is None:
        return "inconclusive"
    return "achieved" if value >= target else "not_achieved"


def record_outcome(
    mission_path: Path,
    root: Path,
    metric: str,
    value: float | None,
    target: float | None,
    evidence_class: str,
    source: str | None = None,
    notes: str = "",
) -> dict:
    """Append a hash-linked outcome while preserving evidence-quality boundaries."""
    verification = verify_mission(mission_path)
    if not verification["valid"]:
        raise ProductMissionError(
            "MISSION_INPUT_DRIFT", "; ".join(verification["errors"])
        )
    _validate_outcome(metric, value, target, evidence_class, source, notes)
    mission = _load_mission(mission_path)
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
    paths = (
        [directory / f"{mission_id}.jsonl"]
        if mission_id
        else sorted(directory.glob("*.jsonl"))
        if directory.exists()
        else []
    )
    records = []
    chain_errors = []
    for path in paths:
        previous = None
        if not path.exists():
            continue
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1
        ):
            if not line.strip():
                continue
            record = json.loads(line)
            core = {
                key: value for key, value in record.items() if key != "record_sha256"
            }
            if record.get("previous_sha256") != previous or record.get(
                "record_sha256"
            ) != _sha_bytes(_canonical(core)):
                chain_errors.append(f"{path.name}:{line_number}")
            previous = record.get("record_sha256")
            records.append(record)
    classes = {
        name: sum(item.get("evidence_class") == name for item in records)
        for name in sorted(EVIDENCE_CLASSES)
    }
    return {
        "schema": "factory.outcome.summary.v1",
        "records": len(records),
        "evidence_classes": classes,
        "verdicts": {
            name: sum(item.get("verdict") == name for item in records)
            for name in ("achieved", "not_achieved", "inconclusive")
        },
        "chain_valid": not chain_errors,
        "chain_errors": chain_errors,
        "scope_limits": [
            "Outcome evidence is local and caller-supplied.",
            "Only measured records with a named source support measured product claims.",
        ],
    }
