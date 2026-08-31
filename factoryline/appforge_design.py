"""Deterministic AppForge narrative and iOS design-contract compiler."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json

from .revenueforge import AUTHORITY, RevenueForgeError
from .revenue_evidence import _atomic_json, _local, _read_json, _seal
from .app_review_gate import app_review_gate_projection
from .appforge_quality_audit import quality_audit_projection
from .appforge_submission_assurance import submission_assurance_projection


SCHEMA = "factory.appforge.design-director.v1"
DISCIPLINES = (
    "visual_direction",
    "accessibility",
    "swiftui_design",
    "motion",
    "gestures",
    "performance",
    "color_psychology",
)
NARRATIVE_BEATS = ("mission", "tension", "guidance", "agency", "transformation", "celebration")
BANNED_PATTERNS = {
    "purple_blue_gradient", "emoji_functional_icon", "hidden_cancel", "gesture_only_action",
    "color_only_status", "fixed_readable_text", "unbounded_animation", "generic_centered_hero",
}


def appforge_design_projection(root: Path) -> dict[str, Any]:
    """Return a bounded, hash-verified summary of local AppForge design work."""
    workspace = Path(root).resolve()
    current = 0
    invalid = 0
    latest: dict[str, Any] | None = None
    for path in sorted((workspace / ".factory" / "appforge").glob("*/appforge-design-receipt.json"))[:100]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            expected = value.pop("receipt_sha256")
            valid = (
                value.get("schema") == "factory.appforge.design-receipt.v1"
                and isinstance(expected, str)
                and len(expected) == 64
                and hashlib.sha256(
                    json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest() == expected
            )
            value["receipt_sha256"] = expected
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            valid = False
            value = None
        if valid:
            current += 1
            latest = value
        else:
            invalid += 1
    return {
        "schema": "factory.appforge.design-projection.v1",
        "marker": "APPFORGE_DESIGN_READ_ONLY",
        "action_summary": "Read hash-verified local AppForge design receipts and report the latest review state; do not create, approve, render, or release a design.",
        "current_count": current,
        "invalid_count": invalid,
        "latest": latest,
        "app_review": app_review_gate_projection(workspace),
        "quality_audit": quality_audit_projection(workspace),
        "submission_assurance": submission_assurance_projection(workspace),
        "authority": {**AUTHORITY, "design_intent_override": False, "app_store_claim_publish": False},
        "claim_boundary": "local design-receipt projection; not rendered UI, device proof, accessibility certification, performance proof, or App Review approval",
    }


def _validated_brief(brief: dict[str, Any]) -> set[str]:
    required = ("app_name", "audience", "primary_job", "desired_emotion", "screens")
    if any(not brief.get(key) for key in required) or not isinstance(brief["screens"], list) or not 1 <= len(brief["screens"]) <= 30:
        raise RevenueForgeError("APPFORGE_DESIGN_BRIEF_INVALID", "app_name, audience, primary_job, desired_emotion, and 1-30 screens are required")
    if not all(isinstance(screen, dict) and screen.get("id") and screen.get("user_goal") for screen in brief["screens"]):
        raise RevenueForgeError("APPFORGE_DESIGN_BRIEF_INVALID", "each screen requires id and user_goal")
    prohibited = {str(value) for value in brief.get("prohibited_patterns", [])}
    if prohibited - BANNED_PATTERNS:
        raise RevenueForgeError("APPFORGE_DESIGN_BRIEF_INVALID", "prohibited_patterns contains an unknown pattern")
    return prohibited


def _design_palette(brief: dict[str, Any]) -> dict[str, Any]:
    brand = brief.get("brand") if isinstance(brief.get("brand"), dict) else {}
    return {
        "primary_intent": str(brand.get("primary_intent") or "trust"),
        "accent_intent": str(brand.get("accent_intent") or brief["desired_emotion"]),
        "semantic_tokens_required": ["background", "surface", "text_primary", "text_secondary", "accent", "success", "warning", "error", "info"],
        "constraints": {"normal_text_contrast": "4.5:1", "large_text_contrast": "3:1", "ui_component_contrast": "3:1", "color_only_meaning": False, "dark_mode_independent": True},
    }


def _design_storyboard(brief: dict[str, Any]) -> list[dict[str, Any]]:
    return [{
        "sequence": index + 1,
        "screen_id": str(screen["id"]),
        "user_goal": str(screen["user_goal"]),
        "narrative_beat": NARRATIVE_BEATS[min(index, len(NARRATIVE_BEATS) - 1)],
        "emotional_job": str(screen.get("emotional_job") or brief["desired_emotion"]),
        "primary_action": str(screen.get("primary_action") or "continue"),
        "system_state": str(screen.get("system_state") or "ready"),
        "required_states": ["loading", "empty", "error", "success", "offline"],
        "human_review": True,
    } for index, screen in enumerate(brief["screens"])]


def _design_gates(storyboards: list[dict[str, Any]], brief: dict[str, Any]) -> dict[str, bool]:
    return {
        "user_intent_bound": True,
        "narrative_spine_complete": len(storyboards) == len(brief["screens"]),
        "seven_discipline_review_required": len(DISCIPLINES) == 7,
        "dynamic_type_required": True,
        "voiceover_and_focus_required": True,
        "reduce_motion_required": True,
        "gesture_alternatives_required": True,
        "release_device_profile_required": True,
        "dark_mode_required": True,
        "performance_claims_require_trace": True,
        "app_store_claims_require_task_matrix": True,
        "app_review_rejection_regression_gate_required": True,
    }


def _design_contract(brief: dict[str, Any], source: Path, prohibited: set[str]) -> dict[str, Any]:
    storyboards = _design_storyboard(brief)
    contract = {
        "schema": SCHEMA,
        "marker": "APPFORGE_DESIGN_CONTRACT_COMPILED",
        "action_summary": "Turn confirmed user intent into a story-led iOS storyboard and seven-discipline review contract; do not render, release, or override human design approval.",
        "app": {"name": str(brief["app_name"]), "audience": str(brief["audience"]), "primary_job": str(brief["primary_job"]), "desired_emotion": str(brief["desired_emotion"])},
        "nanna_storytelling": {"beats": list(NARRATIVE_BEATS), "rule": "story clarifies user agency; it never hides price, consequence, system state, or recovery"},
        "disciplines": list(DISCIPLINES),
        "palette": _design_palette(brief),
        "storyboard": storyboards,
        "prohibited_patterns": sorted(BANNED_PATTERNS | prohibited),
        "gates": _design_gates(storyboards, brief),
        "authority": {**AUTHORITY, "design_intent_override": False, "app_store_claim_publish": False},
        "claim_boundary": "compiled design and review contract; not rendered UI, device proof, accessibility certification, performance proof, or App Review approval",
    }
    contract["brief_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    return contract


def compile_appforge_design(root: Path, brief_path: Path, out_dir: Path) -> dict[str, Any]:
    """Compile user design intent into a story-led, reviewable iOS design system."""
    workspace = Path(root).resolve()
    brief, source = _read_json(workspace, brief_path)
    contract = _design_contract(brief, source, _validated_brief(brief))
    storyboards = contract["storyboard"]
    gates = contract["gates"]
    destination = _local(workspace, out_dir, exists=False)
    contract_path = destination / "appforge-design-contract.json"
    storyboard_path = destination / "ios-storyboard.json"
    skill_path = destination / "APPFORGE_DESIGN_DIRECTOR.md"
    _atomic_json(contract_path, contract)
    _atomic_json(storyboard_path, {"schema": "factory.appforge.storyboard.v1", "screens": storyboards})
    skill = f"""# AppForge Design Director\n\n## Ten-second value\nDescribe who the app serves, what they need to accomplish, and how the experience should feel. AppForge turns that intent into a reviewable iOS storyboard, design contract, and exact next checks without hiding uncertainty or taking release authority.\n\n## Start here\n1. **Describe the mission** — audience, primary job, desired emotion, brand constraints, and screen goals.\n2. **Choose a direction** — compare 2-3 materially different concepts; a color swap is not a new direction.\n3. **Review the story** — follow {' -> '.join(NARRATIVE_BEATS)}.\n4. **Inspect every state** — ready, loading, empty, error, success, and offline.\n5. **Approve or revise** — the human keeps design, monetization, release, and publication authority.\n\n## Recognizable actions\n- **Build storyboard**: turn approved intent into ordered screens and user goals.\n- **Review design**: examine visual direction, accessibility, SwiftUI design, motion, gestures, performance, and color psychology.\n- **Check purchase reality**: compare the observed purchase lifecycle with the reviewed product manifest.\n- **Open TestFlight inbox**: normalize an authorized local feedback export without contacting Apple or replying to testers.\n- **Run failure matrix**: challenge ten monetization failure paths; unknown never becomes pass.\n- **Check policy drift**: identify which reviewed conclusions require human reassessment after an official-source hash changes.\n- **Use evidence memory**: retrieve an unexpired, human-approved exact-app lesson as guidance, never as proof of the current build.\n\n## Nanna narrative discipline\nUse story to make the user's journey easier to understand: establish the mission, name the tension, provide guidance, return agency, show transformation, and end with a calm celebration. Each beat must clarify the user's choice or system state. Never manufacture urgency, shame, dependency, or emotional pressure.\n\n## Operating order\n1. Bind the user's audience, job, desired emotion, brand constraints, and screen goals.\n2. Apply the Nanna narrative spine: {' -> '.join(NARRATIVE_BEATS)}.\n3. Present 2-3 design directions before selection; never treat a color swap as a distinct direction.\n4. Compile semantic design tokens, screen storyboard, real system states, and one signature detail per screen.\n5. Review all seven disciplines: {', '.join(DISCIPLINES)}.\n6. Block on missing human intent, gesture-only actions, color-only meaning, inaccessible motion, unmeasured performance claims, or unsupported App Store claims.\n7. End with a human review packet: what changed, why it serves the user, unresolved evidence, and exact next validation.\n\n## Stop and recovery\nEvery blocked or unknown result must name: what is missing, why it matters, the smallest safe next action, who must approve it, and which receipt will show completion. Never end with a generic error or ask a novice to infer the next command.\n\n## Non-negotiable boundary\nStorytelling may improve comprehension and emotional coherence. It may never hide price, risk, cancellation, recovery, system state, or consequential action. Current-build device, accessibility, performance, and App Store evidence must be collected separately.\n"""
    skill += "\n## Function summaries\nBefore executing any action, show a one-sentence Action summary stating what will happen, which inputs will be read, which artifacts may be written, and which external actions remain locked. After execution, repeat the summary with the status, evidence, changes, untouched boundaries, and next safe action.\n"
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    skill_path.write_text(skill, encoding="utf-8", newline="\n")
    receipt = {
        "schema": "factory.appforge.design-receipt.v1",
        "marker": "APPFORGE_DESIGN_WORKSPACE_WRITTEN",
        "action_summary": contract["action_summary"],
        "contract_sha256": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
        "artifacts": {"contract": contract_path.relative_to(workspace).as_posix(), "storyboard": storyboard_path.relative_to(workspace).as_posix(), "skill": skill_path.relative_to(workspace).as_posix()},
        "gates": gates,
        "authority": contract["authority"],
        "claim_boundary": contract["claim_boundary"],
    }
    return _seal(workspace, destination / "appforge-design-receipt.json", receipt)
