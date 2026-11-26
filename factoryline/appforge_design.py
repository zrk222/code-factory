"""Deterministic AppForge narrative and iOS design-contract compiler."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json
from collections.abc import Callable, Iterator

from . import canonical_sha, compat_sha
from .revenueforge import AUTHORITY, RevenueForgeError
from .revenue_evidence import _atomic_json, _local, _read_json, _seal
from .app_review_gate import app_review_gate_projection
from .appforge_quality_audit import quality_audit_projection
from .appforge_submission_assurance import submission_assurance_projection
from .appforge_evidence_kit import appforge_init_projection
from .appforge_oracle import appforge_oracle_projection
from .appforge_eas import appforge_eas_projection
from .appforge_device_reality import device_reality_projection
from .appforge_release_rehearsal import release_rehearsal_projection
from .appforge_native_surface import native_surface_projection
from .appforge_surface_matrix import surface_matrix_projection
from .appforge_storefront_story import storefront_story_projection
from .appforge_fastlane_capture import fastlane_capture_projection
from .appforge_submission_integrity import submission_integrity_projection
from .appforge_mobile_evidence import mobile_evidence_projection
from .revenue_evidence import read_receipt, receipt_paths


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
NARRATIVE_BEATS = (
    "mission",
    "tension",
    "guidance",
    "agency",
    "transformation",
    "celebration",
)
BANNED_PATTERNS = {
    "purple_blue_gradient",
    "emoji_functional_icon",
    "hidden_cancel",
    "gesture_only_action",
    "color_only_status",
    "fixed_readable_text",
    "unbounded_animation",
    "generic_centered_hero",
}


def _design_status(workspace: Path) -> dict[str, Any]:
    current = 0
    invalid = 0
    latest: dict[str, Any] | None = None
    base = workspace / ".factory" / "appforge"
    for path in sorted(base.glob("*/appforge-design-receipt.json"))[:100]:
        try:
            value = read_receipt(workspace, path)
            expected = value.pop("receipt_sha256")
            valid = (
                value.get("schema") == "factory.appforge.design-receipt.v1"
                and isinstance(expected, str)
                and len(expected) == 64
                and hashlib.sha256(
                    json.dumps(
                        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ).hexdigest()
                == expected
            )
            value["receipt_sha256"] = expected
        except (OSError, ValueError, KeyError, TypeError):
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
        "authority": {
            **AUTHORITY,
            "design_intent_override": False,
            "app_store_claim_publish": False,
        },
        "claim_boundary": "local design-receipt projection; not rendered UI, device proof, accessibility certification, performance proof, or App Review approval",
    }


_STAGES: dict[str, tuple[Callable[..., dict[str, Any]], str]] = {
    "init": (appforge_init_projection, "appforge-init"),
    "design": (_design_status, "appforge-design"),
    "native_surface": (native_surface_projection, "appforge-native-surface"),
    "surface_matrix": (surface_matrix_projection, "appforge-surface-matrix"),
    "device_reality": (device_reality_projection, "device-reality-gate"),
    "eas_preflight": (appforge_eas_projection, "appforge-eas"),
    "mobile_evidence": (mobile_evidence_projection, "appforge-mobile-evidence"),
    "fastlane_capture": (fastlane_capture_projection, "appforge-fastlane-capture"),
    "storefront_story": (storefront_story_projection, "appforge-storefront-story"),
    "app_review": (app_review_gate_projection, "app-review-gate"),
    "quality_audit": (quality_audit_projection, "quality-audit"),
    "oracle_authority": (appforge_oracle_projection, "appforge-oracle"),
    "submission_integrity": (
        submission_integrity_projection,
        "appforge-submission-integrity",
    ),
    "submission_assurance": (submission_assurance_projection, "submission-assurance"),
    "release_rehearsal": (release_rehearsal_projection, "appforge-rehearse"),
}


def appforge_design_projection(
    root: Path, *, stage: str | None = None
) -> dict[str, Any]:
    """Inspect one AppForge stage or reuse one path inventory for full status."""
    workspace = Path(root).resolve()
    if stage is not None:
        selected = _STAGES.get(stage.replace("-", "_"))
        if selected is None:
            choices = ", ".join(name.replace("_", "-") for name in _STAGES)
            raise RevenueForgeError(
                "APPFORGE_STATUS_STAGE_UNKNOWN",
                f"Unknown AppForge stage. Choose from {choices}.",
            )
        project, command = selected
        status = project(workspace)
        return {
            "schema": "factory.appforge.stage-projection.v1",
            "marker": "APPFORGE_STAGE_READ_ONLY",
            "stage": stage.replace("_", "-"),
            "status": status,
            "repair_messages": _focused_repair_messages(workspace, status),
            "help_command": ["factory", "revenue", command, "--help"],
        }
    inventory = tuple(receipt_paths(workspace, "*.json"))
    return {
        **_design_status(workspace),
        **{
            name: project(workspace, inventory=inventory)
            for name, (project, _) in _STAGES.items()
            if name != "design"
        },
    }


def _repair_messages(findings: object) -> Iterator[str]:
    if not isinstance(findings, list):
        return
    for finding in findings[:10]:
        if not isinstance(finding, dict):
            continue
        for key in ("detail", "message", "remediation", "repair"):
            value = finding.get(key)
            if isinstance(value, str) and value.strip():
                yield value[:500]


def _focused_repair_messages(workspace: Path, status: dict[str, Any]) -> list[str]:
    latest = status.get("latest") or {}
    findings = latest.get("findings")
    if findings:
        return list(dict.fromkeys(_repair_messages(findings)))
    path = latest.get("path")
    if (
        not isinstance(path, str)
        or latest.get("ok") is not False
        and "BLOCKED" not in str(latest.get("marker", ""))
    ):
        return []
    try:
        receipt, _ = _read_json(workspace, Path(path))
    except (RevenueForgeError, OSError, RuntimeError, ValueError):
        return []
    seal = receipt.pop("receipt_sha256", None)
    if seal == latest.get("receipt_sha256") and seal in (
        canonical_sha(receipt),
        compat_sha(receipt),
    ):
        return list(dict.fromkeys(_repair_messages(receipt.get("findings"))))
    return []


def _stage_status_lines(label: str, status: dict[str, Any]) -> Iterator[str]:
    latest = status.get("latest") or {}
    marker = latest.get("marker")
    if status.get("invalid_count"):
        yield f"{label} needs evidence review"
        yield from status.get("blockers", {}).values()
        invalid = status.get("invalid")
        if isinstance(invalid, list):
            yield from (f"Stale or invalid receipt {path}" for path in invalid[:10])
    if isinstance(marker, str):
        path = latest.get("path")
        yield f"{label}  {marker}" + (f"  {path}" if isinstance(path, str) else "")
    elif status.get("current_count"):
        yield f"{label} has {status['current_count']} local receipts"
    elif not status.get("invalid_count"):
        yield f"{label} has no local receipts"


def appforge_status_brief(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """The compact status: one row per stage that has receipts, plus the next command."""
    stages = {}
    for name in _STAGES:
        status = payload if name == "design" else payload.get(name, {})
        latest = status.get("latest") or {}
        if status.get("current_count") or status.get("invalid_count"):
            stages[name.replace("_", "-")] = {"marker": latest.get("marker"), "ok": _stage_state(status) == "done",
                                              "path": latest.get("path")}
    step = appforge_next(root)
    return {"schema": "factory.appforge.status-brief.v1", "marker": "APPFORGE_DESIGN_READ_ONLY", "stages": stages,
            "next": {key: step[key] for key in ("stage", "argv", "inputs_missing", "human_required")}}


def _next_line(payload: dict[str, Any]) -> Iterator[str]:
    step = payload if "argv" in payload else payload.get("next")
    if not isinstance(step, dict):
        return
    if step.get("argv"):
        missing = step.get("inputs_missing") or []
        yield "next: " + " ".join(step["argv"]) + (f"  (also supply: {' '.join(missing)})" if missing else "")
    elif step.get("stage") == "complete":
        yield "next: every AppForge stage has a current receipt"


def appforge_status_lines(payload: dict[str, Any]) -> Iterator[str]:
    """Render evidence status without treating an inspection as a readiness gate."""
    if payload.get("schema") in {"factory.appforge.next.v1", "factory.appforge.status-brief.v1"}:
        for name, row in (payload.get("stages") or {}).items():
            yield f"{name}  {row['marker']}  {row['path']}"
        if payload.get("stage") and payload.get("why"):
            yield f"{payload['stage']}: {payload['why']}"
        yield from _next_line(payload)
        return
    stage = payload.get("stage")
    if stage is not None:
        yield from _stage_status_lines(stage, payload["status"])
        yield from payload.get("repair_messages", [])
        yield " ".join(payload["help_command"])
        return
    found = False
    for name in _STAGES:
        status = payload if name == "design" else payload[name]
        if status.get("current_count") or status.get("invalid_count"):
            found = True
            yield from _stage_status_lines(name.replace("_", "-"), status)
            yield from _repair_messages((status.get("latest") or {}).get("findings"))
    if not found:
        yield "No local AppForge receipts. Start with factory revenue appforge-init --help."
    yield from _next_line(payload)


def _validated_brief(brief: dict[str, Any]) -> set[str]:
    required = ("app_name", "audience", "primary_job", "desired_emotion", "screens")
    if (
        any(not brief.get(key) for key in required)
        or not isinstance(brief["screens"], list)
        or not 1 <= len(brief["screens"]) <= 30
    ):
        raise RevenueForgeError(
            "APPFORGE_DESIGN_BRIEF_INVALID",
            "app_name, audience, primary_job, desired_emotion, and 1-30 screens are required",
        )
    if not all(
        isinstance(screen, dict) and screen.get("id") and screen.get("user_goal")
        for screen in brief["screens"]
    ):
        raise RevenueForgeError(
            "APPFORGE_DESIGN_BRIEF_INVALID", "each screen requires id and user_goal"
        )
    prohibited = {str(value) for value in brief.get("prohibited_patterns", [])}
    if prohibited - BANNED_PATTERNS:
        raise RevenueForgeError(
            "APPFORGE_DESIGN_BRIEF_INVALID",
            "prohibited_patterns contains an unknown pattern",
        )
    return prohibited


def _design_palette(brief: dict[str, Any]) -> dict[str, Any]:
    brand = brief.get("brand")
    if not isinstance(brand, dict):
        brand = {}
    return {
        "primary_intent": str(brand.get("primary_intent") or "trust"),
        "accent_intent": str(brand.get("accent_intent") or brief["desired_emotion"]),
        "semantic_tokens_required": [
            "background",
            "surface",
            "text_primary",
            "text_secondary",
            "accent",
            "success",
            "warning",
            "error",
            "info",
        ],
        "constraints": {
            "normal_text_contrast": "4.5:1",
            "large_text_contrast": "3:1",
            "ui_component_contrast": "3:1",
            "color_only_meaning": False,
            "dark_mode_independent": True,
        },
    }


def _design_storyboard(brief: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "sequence": index + 1,
            "screen_id": str(screen["id"]),
            "user_goal": str(screen["user_goal"]),
            "narrative_beat": NARRATIVE_BEATS[min(index, len(NARRATIVE_BEATS) - 1)],
            "emotional_job": str(
                screen.get("emotional_job") or brief["desired_emotion"]
            ),
            "primary_action": str(screen.get("primary_action") or "continue"),
            "system_state": str(screen.get("system_state") or "ready"),
            "required_states": ["loading", "empty", "error", "success", "offline"],
            "human_review": True,
        }
        for index, screen in enumerate(brief["screens"])
    ]


def _design_gates(
    storyboards: list[dict[str, Any]], brief: dict[str, Any]
) -> dict[str, bool]:
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


def _design_contract(
    brief: dict[str, Any], source: Path, prohibited: set[str]
) -> dict[str, Any]:
    storyboards = _design_storyboard(brief)
    contract = {
        "schema": SCHEMA,
        "marker": "APPFORGE_DESIGN_CONTRACT_COMPILED",
        "action_summary": "Turn confirmed user intent into a story-led iOS storyboard and seven-discipline review contract; do not render, release, or override human design approval.",
        "app": {
            "name": str(brief["app_name"]),
            "audience": str(brief["audience"]),
            "primary_job": str(brief["primary_job"]),
            "desired_emotion": str(brief["desired_emotion"]),
        },
        "nanna_storytelling": {
            "beats": list(NARRATIVE_BEATS),
            "rule": "story clarifies user agency; it never hides price, consequence, system state, or recovery",
        },
        "disciplines": list(DISCIPLINES),
        "palette": _design_palette(brief),
        "storyboard": storyboards,
        "prohibited_patterns": sorted(BANNED_PATTERNS | prohibited),
        "gates": _design_gates(storyboards, brief),
        "authority": {
            **AUTHORITY,
            "design_intent_override": False,
            "app_store_claim_publish": False,
        },
        "claim_boundary": "compiled design and review contract; not rendered UI, device proof, accessibility certification, performance proof, or App Review approval",
    }
    contract["brief_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    return contract


def compile_appforge_design(
    root: Path, brief_path: Path, out_dir: Path
) -> dict[str, Any]:
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
    _atomic_json(
        storyboard_path,
        {"schema": "factory.appforge.storyboard.v1", "screens": storyboards},
    )
    skill = f"""# AppForge Design Director\n\n## Ten-second value\nDescribe who the app serves, what they need to accomplish, and how the experience should feel. AppForge turns that intent into a reviewable iOS storyboard, design contract, and exact next checks without hiding uncertainty or taking release authority.\n\n## Start here\n1. **Describe the mission** — audience, primary job, desired emotion, brand constraints, and screen goals.\n2. **Choose a direction** — compare 2-3 materially different concepts; a color swap is not a new direction.\n3. **Review the story** — follow {" -> ".join(NARRATIVE_BEATS)}.\n4. **Inspect every state** — ready, loading, empty, error, success, and offline.\n5. **Approve or revise** — the human keeps design, monetization, release, and publication authority.\n\n## Recognizable actions\n- **Build storyboard**: turn approved intent into ordered screens and user goals.\n- **Review design**: examine visual direction, accessibility, SwiftUI design, motion, gestures, performance, and color psychology.\n- **Check purchase reality**: compare the observed purchase lifecycle with the reviewed product manifest.\n- **Open TestFlight inbox**: normalize an authorized local feedback export without contacting Apple or replying to testers.\n- **Run failure matrix**: challenge ten monetization failure paths; unknown never becomes pass.\n- **Check policy drift**: identify which reviewed conclusions require human reassessment after an official-source hash changes.\n- **Use evidence memory**: retrieve an unexpired, human-approved exact-app lesson as guidance, never as proof of the current build.\n\n## Nanna narrative discipline\nUse story to make the user's journey easier to understand: establish the mission, name the tension, provide guidance, return agency, show transformation, and end with a calm celebration. Each beat must clarify the user's choice or system state. Never manufacture urgency, shame, dependency, or emotional pressure.\n\n## Operating order\n1. Bind the user's audience, job, desired emotion, brand constraints, and screen goals.\n2. Apply the Nanna narrative spine: {" -> ".join(NARRATIVE_BEATS)}.\n3. Present 2-3 design directions before selection; never treat a color swap as a distinct direction.\n4. Compile semantic design tokens, screen storyboard, real system states, and one signature detail per screen.\n5. Review all seven disciplines: {", ".join(DISCIPLINES)}.\n6. Block on missing human intent, gesture-only actions, color-only meaning, inaccessible motion, unmeasured performance claims, or unsupported App Store claims.\n7. End with a human review packet: what changed, why it serves the user, unresolved evidence, and exact next validation.\n\n## Stop and recovery\nEvery blocked or unknown result must name: what is missing, why it matters, the smallest safe next action, who must approve it, and which receipt will show completion. Never end with a generic error or ask a novice to infer the next command.\n\n## Non-negotiable boundary\nStorytelling may improve comprehension and emotional coherence. It may never hide price, risk, cancellation, recovery, system state, or consequential action. Current-build device, accessibility, performance, and App Store evidence must be collected separately.\n"""
    skill += "\n## Function summaries\nBefore executing any action, show a one-sentence Action summary stating what will happen, which inputs will be read, which artifacts may be written, and which external actions remain locked. After execution, repeat the summary with the status, evidence, changes, untouched boundaries, and next safe action.\n"
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    skill_bytes = skill.encode("utf-8")
    try:
        unchanged_skill = (
            skill_path.is_file()
            and not skill_path.is_symlink()
            and skill_path.stat().st_nlink == 1
            and skill_path.read_bytes() == skill_bytes
        )
    except OSError:
        unchanged_skill = False
    if not unchanged_skill:
        skill_path.write_text(skill, encoding="utf-8", newline="\n")
    receipt = {
        "schema": "factory.appforge.design-receipt.v1",
        "marker": "APPFORGE_DESIGN_WORKSPACE_WRITTEN",
        "action_summary": contract["action_summary"],
        "contract_sha256": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
        "artifacts": {
            "contract": contract_path.relative_to(workspace).as_posix(),
            "storyboard": storyboard_path.relative_to(workspace).as_posix(),
            "skill": skill_path.relative_to(workspace).as_posix(),
        },
        "gates": gates,
        "authority": contract["authority"],
        "claim_boundary": contract["claim_boundary"],
    }
    return _seal(workspace, destination / "appforge-design-receipt.json", receipt)


# Ordered AppForge chain for `factory appforge next`. Flag sources: "init:<artifact>" and "kit:<artifact>" come
# from the latest init / evidence-kit receipt; "out:<path>" is the producing stage's default --out; None means a
# person must supply it. human=True marks stages that need observed evidence, not just a command.
_O = ".factory/appforge/"
_NEXT_CHAIN: tuple[tuple[str, str, dict[str, str | None], bool], ...] = (
    ("init", "appforge-init", {"--out-dir": None, "--app-name": None, "--bundle-identifier": None,
                                "--version": None, "--build-number": None, "--audience": None,
                                "--primary-job": None, "--desired-emotion": None}, True),
    ("design", "appforge-design", {"--brief": "init:design_brief", "--out-dir": f"out:{_O}design"}, False),
    ("evidence_kit", "evidence-kit", {"--candidate": "init:candidate", "--design-input": "init:user_design_input",
                                      "--out-dir": f"out:{_O}evidence"}, False),
    ("native_surface", "appforge-native-surface", {"--candidate": "kit:candidate", "--contract": None,
                                                   "--evidence": None}, True),
    ("surface_matrix", "appforge-surface-matrix", {"--candidate": "kit:candidate",
                                                   "--native-surface": f"out:{_O}native-surface.json"}, False),
    ("app_review", "app-review-gate", {"--contract": "kit:app_review_contract",
                                       "--evidence": "kit:app_review_evidence"}, True),
    ("store_media", "store-media-gate", {"--contract": "kit:store_media_contract",
                                         "--evidence": "kit:store_media_evidence"}, True),
    ("storefront_story", "appforge-storefront-story", {"--candidate": "kit:candidate",
                                                       "--store-media": f"out:{_O}store-media.json",
                                                       "--contract": None, "--evidence": None}, True),
    ("fastlane_capture", "appforge-fastlane-capture", {"--candidate": "kit:candidate",
                                                       "--surface-matrix": f"out:{_O}surface-matrix.json",
                                                       "--storefront-story": f"out:{_O}storefront-story.json",
                                                       "--contract": None}, True),
    ("submission_integrity", "appforge-submission-integrity", {"--candidate": "kit:candidate",
                                                               "--contract": None}, True),
    ("quality_audit", "quality-audit", {"--contract": "kit:quality_contract",
                                        "--evidence": "kit:quality_evidence"}, True),
    ("oracle_authority", "appforge-oracle", {"--authority": "kit:oracle_authority"}, True),
    ("eas_preflight", "appforge-eas", {"--candidate": "kit:candidate", "--eas-json": None,
                                       "--build-profile": None, "--submit-profile": None}, False),
    ("submission_assurance", "submission-assurance", {"--contract": "kit:assurance_contract",
                                                      "--app-review": f"out:{_O}app-review.json",
                                                      "--store-media": f"out:{_O}store-media.json",
                                                      "--saas-proof": None,
                                                      "--quality-audit": f"out:{_O}quality-audit.json"}, True),
    ("release_rehearsal", "appforge-rehearse", {"--candidate": "kit:candidate",
                                                "--submission-assurance": f"out:{_O}submission-assurance.json",
                                                "--profile": None}, False),
)
_RECEIPT_ONLY = {"evidence_kit": "appforge-evidence-kit-receipt.json", "store_media": "store-media*.json"}


def _sealed_receipt(workspace: Path, path: Path) -> dict[str, Any] | None:
    try:
        value = read_receipt(workspace, path)
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    seal = value.pop("receipt_sha256", None)
    return value if seal in (canonical_sha(value), compat_sha(value)) and seal is not None else None


def _receipt_only_status(workspace: Path, pattern: str) -> dict[str, Any]:
    current = [(path, value) for path in sorted(receipt_paths(workspace, pattern))[:100]
               if (value := _sealed_receipt(workspace, path)) is not None]
    if not current:
        return {"current_count": 0}
    path, value = current[-1]
    latest = {"path": path.relative_to(workspace).as_posix(), "ok": value.get("ok"), "marker": value.get("marker"),
              "artifacts": value.get("artifacts"), "candidate": value.get("candidate"), "findings": value.get("findings")}
    return {"current_count": len(current), "latest": latest}


def _stage_state(status: dict[str, Any]) -> str:
    latest = status.get("latest") or {}
    if not status.get("current_count"):
        return "missing"
    if latest.get("ok") is False or "BLOCKED" in str(latest.get("marker", "")):
        return "blocked"
    return "done"


def _flag_value(source: str | None, artifacts: dict[str, dict[str, Any]]) -> str | None:
    if source is None:
        return None
    kind, _, value = source.partition(":")
    if kind == "out":
        return value
    path = (artifacts.get(kind) or {}).get(value)
    return path if isinstance(path, str) else None


def _next_argv(command: str, flags: dict[str, str | None], artifacts: dict[str, dict[str, Any]]):
    argv, missing = ["factory", "revenue", command, "--root", "."], []
    for flag, source in flags.items():
        value = _flag_value(source, artifacts)
        if value is None:
            missing.append(flag)
        else:
            argv += [flag, value]
    return argv + ["--json"], missing


def _candidate_drift(statuses: dict[str, dict[str, Any]], current: object) -> list[str]:
    """Stages whose latest receipt binds a different release candidate than the newest one."""
    stale = []
    for name, status in statuses.items():
        bound = (status.get("latest") or {}).get("candidate")
        if isinstance(bound, dict) and isinstance(current, dict) and bound != current:
            stale.append(name.replace("_", "-"))
    return stale


def appforge_next(root: Path) -> dict[str, Any]:
    """The first AppForge stage without a current valid receipt, and the command that produces it. Runs nothing."""
    workspace = Path(root).resolve()
    projection = appforge_design_projection(workspace)
    statuses = {name: (projection if name == "design" else
                       _receipt_only_status(workspace, _RECEIPT_ONLY[name]) if name in _RECEIPT_ONLY else
                       projection.get(name, {}))
                for name, *_ in _NEXT_CHAIN}
    init_latest = statuses["init"].get("latest") or {}
    init_artifacts = {}
    if init_latest.get("path"):
        receipt = _sealed_receipt(workspace, workspace / init_latest["path"])
        init_artifacts = (receipt or {}).get("artifacts") or {}
    artifacts = {"init": init_artifacts,
                 "kit": (statuses["evidence_kit"].get("latest") or {}).get("artifacts") or {}}
    result: dict[str, Any] = {"schema": "factory.appforge.next.v1", "marker": "APPFORGE_NEXT_READ_ONLY",
                              "stale_for_candidate": _candidate_drift(statuses, init_latest.get("candidate")),
                              "authority": "none", "runs_nothing": True}
    for name, command, flags, human in _NEXT_CHAIN:
        state = _stage_state(statuses[name])
        if state == "done":
            continue
        argv, missing = _next_argv(command, flags, artifacts)
        why = ("latest receipt is blocked: " + "; ".join(_repair_messages((statuses[name].get("latest") or {})
                                                                          .get("findings")))[:500]
               if state == "blocked" else "no current valid receipt")
        return result | {"stage": name.replace("_", "-"), "state": state, "why": why, "argv": argv,
                         "inputs_missing": missing, "human_required": human or bool(missing)}
    return result | {"stage": "complete", "state": "done", "why": "every stage has a current valid receipt",
                     "argv": None, "inputs_missing": [], "human_required": False}
