"""Compile explicit FactoryLine policy into deterministic required checks.

The compiler is intentionally boring: it accepts the versioned JSON policy
already used by ``factory policy`` and emits a stable, hash-bound check
manifest.  It never interprets prose, calls a model, runs a check, or grants
authority.  Unknown or malformed policy rules remain visible as review-needed
items instead of being silently ignored.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
from typing import Any


POLICY_SCHEMA = "factory.policy.v1"
COMPILED_SCHEMA = "factory.enterprise-policy-checks.v1"

_BOOL_RULES: dict[tuple[str, str], tuple[str, str]] = {
    ("release", "require_ci"): ("ci", "required-evidence"),
    ("release", "require_clean_install"): ("clean-install", "required-evidence"),
    ("release", "require_license"): ("license", "required-evidence"),
    ("quality", "require_hollow_tests"): ("hollow-tests", "verification"),
    ("quality", "require_hollow_validators"): ("hollow-validators", "verification"),
    ("tokens", "require_meter"): ("meter", "required-evidence"),
    ("design", "require_prestige_audit"): ("prestige-audit", "verification"),
}
_NUMBER_RULES: dict[tuple[str, str], tuple[str, str, str]] = {
    ("quality", "min_goldens"): ("goldens", "gte", "threshold"),
    ("quality", "max_complexity_delta"): ("complexity-delta", "lte", "threshold"),
    ("tokens", "max_estimated_cost_usd"): ("estimated-cost-usd", "lte", "threshold"),
}
_KNOWN_SECTIONS = frozenset({"schema", "risk", "quality", "tokens", "design", "release"})
_KNOWN_RISK_KEYS = frozenset({"default", "require_human_approval_for"})
_KNOWN_KEYS = {
    "risk": _KNOWN_RISK_KEYS,
    "quality": frozenset({key for section, key in (*_BOOL_RULES, *_NUMBER_RULES) if section == "quality"}),
    "tokens": frozenset({key for section, key in (*_BOOL_RULES, *_NUMBER_RULES) if section == "tokens"}),
    "design": frozenset({"purpose_profile", "require_prestige_audit"}),
    "release": frozenset({key for section, key in _BOOL_RULES if section == "release"}),
}
_KNOWN_ENUMS = {"risk.default": frozenset({"human", "supervised", "autonomous"})}


class PolicyCompileError(ValueError):
    """Stable fail-closed policy compiler error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PolicyCompileError("E_POLICY_NOT_CANONICAL", f"policy is not canonical JSON: {exc}") from exc


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _load_policy(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyCompileError("E_POLICY_INPUT_INVALID", f"unable to read policy: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != POLICY_SCHEMA:
        raise PolicyCompileError("E_POLICY_SCHEMA_UNSUPPORTED", f"policy schema must be {POLICY_SCHEMA}")
    return value


def _workspace_path(root: Path, supplied: Path) -> Path:
    workspace = Path(root).resolve()
    path = supplied if supplied.is_absolute() else workspace / supplied
    resolved = path.resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise PolicyCompileError("E_POLICY_PATH_ESCAPE", "policy path must remain inside the workspace") from exc
    return resolved


def _section(policy: dict[str, Any], name: str, review: list[dict[str, Any]]) -> dict[str, Any]:
    value = policy.get(name, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        review.append({"path": name, "reason": "section must be an object"})
        return {}
    return value


def _sections(policy: dict[str, Any], review: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return typed known sections and retain malformed-section findings."""
    sections = {name: _section(policy, name, review) for name in ("risk", "quality", "tokens", "design", "release")}
    unknown_sections = sorted(set(policy) - _KNOWN_SECTIONS)
    for name in unknown_sections:
        review.append({"path": name, "reason": "unsupported policy section"})
    for section_name, section in sections.items():
        for key in sorted(set(section) - _KNOWN_KEYS[section_name]):
            review.append({"path": f"{section_name}.{key}", "reason": "unsupported policy rule"})
    return sections


def _compile_boolean_checks(sections: dict[str, dict[str, Any]], review: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for (section_name, key), (check_name, kind) in sorted(_BOOL_RULES.items()):
        section = sections[section_name]
        if key not in section:
            continue
        value = section[key]
        if not isinstance(value, bool):
            review.append({"path": f"{section_name}.{key}", "reason": "rule must be boolean"})
            continue
        checks.append({
            "id": f"policy.{section_name}.{key}",
            "name": check_name,
            "kind": kind,
            "enabled": value,
            "evidence_key": check_name,
        })
    return checks


def _compile_numeric_checks(sections: dict[str, dict[str, Any]], review: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for (section_name, key), (check_name, operator, kind) in sorted(_NUMBER_RULES.items()):
        section = sections[section_name]
        if key not in section:
            continue
        value = section[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            review.append({"path": f"{section_name}.{key}", "reason": "rule must be a non-negative number"})
            continue
        checks.append({
            "id": f"policy.{section_name}.{key}",
            "name": check_name,
            "kind": kind,
            "enabled": True,
            "operator": operator,
            "value": value,
            "evidence_key": check_name,
        })
    return checks


def _compile_risk_gates(risk: dict[str, Any], review: list[dict[str, Any]]) -> list[dict[str, Any]]:
    human_gates: list[dict[str, Any]] = []
    default = risk.get("default")
    if default is not None:
        if not isinstance(default, str) or default not in _KNOWN_ENUMS["risk.default"]:
            review.append({"path": "risk.default", "reason": "must be human, supervised, or autonomous"})
        else:
            human_gates.append({"id": "policy.risk.default", "mode": default, "authority": "none"})
    requested = risk.get("require_human_approval_for", [])
    if requested is not None:
        if not isinstance(requested, list) or not all(isinstance(item, str) and item.strip() for item in requested):
            review.append({"path": "risk.require_human_approval_for", "reason": "rule must be a list of non-empty strings"})
        else:
            for action in sorted(set(item.strip() for item in requested)):
                human_gates.append({
                    "id": f"policy.risk.human-approval.{action}",
                    "action_class": action,
                    "authority": "human-required",
                })
    return human_gates


def _compile_purpose_gate(design: dict[str, Any], review: list[dict[str, Any]]) -> list[dict[str, Any]]:
    human_gates: list[dict[str, Any]] = []
    purpose = design.get("purpose_profile")
    if purpose is not None:
        if not isinstance(purpose, str) or not purpose.strip():
            review.append({"path": "design.purpose_profile", "reason": "purpose profile must be a non-empty string"})
        else:
            human_gates.append({"id": "policy.design.purpose-profile", "purpose": purpose.strip(), "authority": "none"})
    return human_gates


def _markers(checks: list[dict[str, Any]], human_gates: list[dict[str, Any]], review: list[dict[str, Any]]) -> list[str]:
    markers = ["POLICY_INPUT_ACCEPTED", "POLICY_MANIFEST_BOUND"]
    if checks:
        markers.append("POLICY_RULE_COMPILED")
    if human_gates:
        markers.append("POLICY_GATE_EXPLICIT")
    if review:
        markers.append("POLICY_REVIEW_REQUIRED")
    return markers


def compile_policy(root: Path, policy: Path) -> dict[str, Any]:
    """Compile one policy file into a stable, reviewable check manifest."""
    path = _workspace_path(root, Path(policy))
    supplied = _load_policy(path)
    review: list[dict[str, Any]] = []
    sections = _sections(supplied, review)
    checks = _compile_boolean_checks(sections, review) + _compile_numeric_checks(sections, review)
    human_gates = _compile_risk_gates(sections["risk"], review) + _compile_purpose_gate(sections["design"], review)
    checks.sort(key=lambda item: item["id"])
    human_gates.sort(key=lambda item: item["id"])
    review.sort(key=lambda item: (item["path"], item["reason"]))
    markers = _markers(checks, human_gates, review)
    body = {
        "schema": COMPILED_SCHEMA,
        "source_schema": POLICY_SCHEMA,
        "source_path": path.relative_to(Path(root).resolve()).as_posix(),
        "policy_sha256": _sha(supplied),
        "checks": checks,
        "human_gates": human_gates,
        "review_required": review,
        "status": "REVIEW_REQUIRED" if review else "COMPILED",
        "markers": markers,
        "authority": {"execute": False, "merge": False, "deploy": False, "release": False, "billing": False},
        "claim_boundary": "compiled policy intent only; no check execution or authority is granted",
    }
    body["manifest_sha256"] = _sha({key: value for key, value in body.items() if key not in {"manifest_sha256", "source_path"}})
    return body


def write_compiled_policy(root: Path, policy: Path, out: Path | None = None) -> dict[str, Any]:
    """Compile and optionally write a policy manifest beneath the workspace."""
    result = compile_policy(root, policy)
    if out is not None:
        destination = _workspace_path(root, Path(out))
        destination.parent.mkdir(parents=True, exist_ok=True)
        final = {**result, "marker": "POLICY_CLI_WRITTEN", "markers": [*result["markers"], "POLICY_CLI_WRITTEN"], "path": str(destination)}
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        try:
            temporary.write_text(json.dumps(final, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            temporary.replace(destination)
        except OSError as exc:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise PolicyCompileError("E_POLICY_OUTPUT", f"unable to write compiled policy: {exc}") from exc
        result = final
    return result
