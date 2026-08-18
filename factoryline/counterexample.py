"""Deterministic intent-to-counterexample planning.

This module is deliberately a planner and verifier, not a test generator or
agent runner.  It makes every declared negative condition inspectable and
tamper-evident, then leaves actual test execution to the approved E2E gate.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any


COUNTEREXAMPLE_SOURCE_SCHEMA = "factory.counterexample-source.v1"
COUNTEREXAMPLE_PLAN_SCHEMA = "factory.counterexample-plan.v1"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_TAGS = frozenset({"boundary", "authorization", "idempotency", "temporal", "state", "validation"})
_MUTATIONS = {
    "boundary": "outside_declared_boundary",
    "authorization": "missing_or_wrong_authority",
    "idempotency": "duplicate_effect_or_request",
    "temporal": "reordered_or_delayed_event",
    "state": "stale_or_conflicting_state",
    "validation": "invalid_or_missing_input",
}


class CounterexampleError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise CounterexampleError("COUNTEREXAMPLE_PATH_INVALID", "path must stay inside the workspace") from exc


def _load(root: Path, path: Path) -> tuple[dict[str, Any], str, str]:
    candidate = Path(path).resolve()
    relative = _relative(root, candidate)
    if not candidate.is_file():
        raise CounterexampleError("COUNTEREXAMPLE_SOURCE_UNREADABLE", "source must name a readable workspace JSON file")
    raw = candidate.read_bytes()
    try:
        source = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CounterexampleError("COUNTEREXAMPLE_SOURCE_INVALID", f"source is not UTF-8 JSON: {exc}") from exc
    if not isinstance(source, dict):
        raise CounterexampleError("COUNTEREXAMPLE_SOURCE_INVALID", "source must contain one JSON object")
    return source, relative, sha256(raw).hexdigest()


def _text(value: object, field: str, *, limit: int = 480, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
        raise CounterexampleError("COUNTEREXAMPLE_SOURCE_INVALID", f"{field} must be a non-empty string of at most {limit} characters")
    result = value.strip()
    if identifier and not _IDENTIFIER.fullmatch(result):
        raise CounterexampleError("COUNTEREXAMPLE_SOURCE_INVALID", f"{field} has an unsupported identifier")
    return result


def _validated_requirement(item: object, index: int, seen: set[str]) -> dict[str, Any]:
    if not isinstance(item, dict) or set(item) != {"id", "statement", "risk_tags"}:
        raise CounterexampleError("COUNTEREXAMPLE_SOURCE_INVALID", f"requirements[{index}] must contain exactly id, statement, and risk_tags")
    requirement_id = _text(item.get("id"), f"requirements[{index}].id", limit=96, identifier=True)
    if requirement_id in seen:
        raise CounterexampleError("COUNTEREXAMPLE_SOURCE_INVALID", "requirement ids must be unique")
    seen.add(requirement_id)
    tags = item.get("risk_tags")
    if not isinstance(tags, list) or not 1 <= len(tags) <= 6:
        raise CounterexampleError("COUNTEREXAMPLE_SOURCE_INVALID", f"requirements[{index}].risk_tags must contain 1 through 6 supported tags")
    if any(not isinstance(tag, str) or tag not in _TAGS for tag in tags) or len(set(tags)) != len(tags):
        raise CounterexampleError("COUNTEREXAMPLE_SOURCE_INVALID", f"requirements[{index}].risk_tags must be unique supported tags")
    return {"id": requirement_id, "statement": _text(item.get("statement"), f"requirements[{index}].statement"), "risk_tags": sorted(tags)}


def validate_counterexample_source(value: object) -> dict[str, Any]:
    """Validate and normalize bounded requirement input for counterexample planning."""
    if not isinstance(value, dict) or set(value) != {"schema", "id", "requirements"}:
        raise CounterexampleError("COUNTEREXAMPLE_SOURCE_INVALID", "source must contain exactly schema, id, and requirements")
    if value.get("schema") != COUNTEREXAMPLE_SOURCE_SCHEMA:
        raise CounterexampleError("COUNTEREXAMPLE_SOURCE_INVALID", f"schema must be {COUNTEREXAMPLE_SOURCE_SCHEMA}")
    requirements = value.get("requirements")
    if not isinstance(requirements, list) or not 1 <= len(requirements) <= 128:
        raise CounterexampleError("COUNTEREXAMPLE_SOURCE_INVALID", "requirements must contain 1 through 128 entries")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(requirements):
        normalized.append(_validated_requirement(item, index, seen))
    return {"schema": COUNTEREXAMPLE_SOURCE_SCHEMA, "id": _text(value.get("id"), "id", limit=96, identifier=True), "requirements": sorted(normalized, key=lambda item: item["id"])}


def _cases(source: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"id": f"{requirement['id']}--{tag}", "requirement_id": requirement["id"], "risk_tag": tag, "mutation": _MUTATIONS[tag], "expected": "negative_proof_must_reject"}
        for requirement in source["requirements"] for tag in requirement["risk_tags"]
    ]


def compile_counterexample_plan(root: Path, source_path: Path) -> dict[str, Any]:
    """Compile deterministic negative-proof obligations without running any test or repair."""
    workspace = Path(root).resolve()
    source, source_relative, source_sha256 = _load(workspace, source_path)
    normalized = validate_counterexample_source(source)
    cases = _cases(normalized)
    core = {
        "schema": COUNTEREXAMPLE_PLAN_SCHEMA,
        "marker": "COUNTEREXAMPLE_PLAN_COMPILED",
        "source": {"path": source_relative, "sha256": source_sha256, "id": normalized["id"]},
        "cases": cases,
        "facts": {"requirement_count": len(normalized["requirements"]), "case_count": len(cases), "risk_tags": sorted({case["risk_tag"] for case in cases})},
        "authority": {"execution": False, "source_write": False, "repair": False, "approval": False, "publication": False, "memory_content": False},
        "scope_limits": ["A case is a declared negative proof obligation, not an executed test.", "The planner never invents commands, edits source, or authorizes a repair."],
    }
    return {**core, "plan_sha256": _sha(core)}


def _counterexample_plan_core(plan: dict[str, Any], relative: str) -> tuple[dict[str, Any], str] | dict[str, Any]:
    supplied_hash = plan.get("plan_sha256")
    core = {key: value for key, value in plan.items() if key != "plan_sha256"}
    if not isinstance(supplied_hash, str) or supplied_hash != _sha(core):
        return {"schema": COUNTEREXAMPLE_PLAN_SCHEMA, "marker": "COUNTEREXAMPLE_PLAN_TAMPERED", "ok": False, "plan_path": relative}
    return core, supplied_hash


def _counterexample_source(plan: dict[str, Any]) -> dict[str, Any]:
    source = plan.get("source")
    if not isinstance(source, dict) or set(source) != {"path", "sha256", "id"}:
        raise CounterexampleError("COUNTEREXAMPLE_PLAN_INVALID", "plan source must contain path, sha256, and id")
    return source


def _counterexample_comparison(plan: dict[str, Any], source: dict[str, Any], current_sha: str, normalized: dict[str, Any], relative: str) -> dict[str, Any]:
    expected = _cases(normalized)
    if source.get("sha256") != current_sha or source.get("id") != normalized["id"]:
        return {"schema": COUNTEREXAMPLE_PLAN_SCHEMA, "marker": "COUNTEREXAMPLE_SOURCE_STALE", "ok": False, "plan_path": relative}
    actual = plan.get("cases")
    if actual != expected:
        return {"schema": COUNTEREXAMPLE_PLAN_SCHEMA, "marker": "HOLLOW_COUNTEREXAMPLE", "ok": False, "plan_path": relative, "expected_case_count": len(expected), "actual_case_count": len(actual) if isinstance(actual, list) else None}
    return {"schema": COUNTEREXAMPLE_PLAN_SCHEMA, "marker": "COUNTEREXAMPLE_PLAN_VERIFIED", "ok": True, "plan_path": relative, "case_count": len(expected), "plan_sha256": plan["plan_sha256"]}


def verify_counterexample_plan(root: Path, plan_path: Path) -> dict[str, Any]:
    """Verify a sealed plan against its current source and expected obligations."""
    workspace = Path(root).resolve()
    plan, plan_relative, _ = _load(workspace, plan_path)
    if not isinstance(plan, dict) or plan.get("schema") != COUNTEREXAMPLE_PLAN_SCHEMA:
        raise CounterexampleError("COUNTEREXAMPLE_PLAN_INVALID", f"plan must use {COUNTEREXAMPLE_PLAN_SCHEMA}")
    integrity = _counterexample_plan_core(plan, plan_relative)
    if isinstance(integrity, dict):
        return integrity
    source = _counterexample_source(plan)
    current, _, current_sha = _load(workspace, workspace / str(source["path"]))
    normalized = validate_counterexample_source(current)
    return _counterexample_comparison(plan, source, current_sha, normalized, plan_relative)


def write_counterexample_plan(plan: dict[str, Any], out_path: Path) -> Path:
    """Atomically write a previously compiled plan to an explicitly selected path."""
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_bytes(_canonical(plan))
    temporary.replace(target)
    return target
