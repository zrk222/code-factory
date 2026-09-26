"""Hash-sealed promotion bridge between SpecLine intent and ForgeLine execution."""

from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import Any
from .revenueforge import AUTHORITY, RevenueForgeError


def _sha(v: object) -> str:
    return hashlib.sha256(
        json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _read(root: Path, path: Path) -> tuple[dict[str, Any], Path]:
    p = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        p.relative_to(root.resolve())
    except ValueError as e:
        raise RevenueForgeError(
            "SPECFORGE_PATH_REJECTED", "paths must stay in workspace"
        ) from e
    try:
        v = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise RevenueForgeError("SPECFORGE_INPUT_INVALID", "inputs must be JSON") from e
    if not isinstance(v, dict):
        raise RevenueForgeError("SPECFORGE_INPUT_INVALID", "inputs must be objects")
    return v, p


def _output(root: Path, path: Path) -> Path:
    """Resolve a receipt destination and reject any path that escapes the workspace before writing."""
    target = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise RevenueForgeError(
            "SPECFORGE_PATH_REJECTED", "output path must stay in workspace"
        ) from exc
    return target


def _validate_spec(spec: dict[str, Any]) -> None:
    valid = (
        set(spec) == {"schema", "intent", "approval", "obligations", "required_gates"}
        and spec.get("schema") == "factory.specline.delivery-packet.v1"
        and isinstance(spec.get("intent"), dict)
        and isinstance(spec.get("obligations"), list)
        and isinstance(spec.get("required_gates"), list)
        and all(isinstance(item, str) and item for item in spec["required_gates"])
    )
    if not valid:
        raise RevenueForgeError(
            "SPECFORGE_SPEC_INVALID",
            "SpecLine packet must contain intent, approval, obligations, and explicit required_gates",
        )


def _spec_findings(spec: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    approval = spec["approval"]
    if not isinstance(approval, dict) or approval.get("origin") not in {
        "human_confirmed",
        "trusted_source",
    }:
        findings.append("E_SPECLINE_AUTHORITY_MISSING")
    obligations = spec["obligations"]
    if not obligations or not all(
        isinstance(item, dict)
        and item.get("id")
        and item.get("forbidden_behavior")
        and item.get("gate")
        for item in obligations
    ):
        findings.append("E_SPECLINE_OBLIGATION_LOOSE")
    return findings


def _forge_findings(
    spec: dict[str, Any], forge: dict[str, Any], digest: str
) -> list[str]:
    findings: list[str] = []
    if (
        set(forge) != {"schema", "intent_sha256", "state", "gates"}
        or forge.get("schema") != "factory.forgeline.delivery-state.v1"
        or forge.get("intent_sha256") != digest
    ):
        findings.append("E_FORGELINE_INTENT_DRIFT")
    gates = forge.get("gates") if isinstance(forge.get("gates"), dict) else {}
    for gate in spec["required_gates"]:
        if gates.get(gate) is not True:
            findings.append("E_FORGELINE_REQUIRED_GATE_MISSING:" + gate)
    if forge.get("state") != "verified":
        findings.append("E_FORGELINE_STATE_NOT_VERIFIED")
    return findings


def _repair_plan(findings: list[str]) -> list[str]:
    plan: list[str] = []
    for finding in findings:
        if finding == "E_FORGELINE_INTENT_DRIFT":
            plan.append(
                "Re-issue ForgeLine state from the exact approved SpecLine intent."
            )
        elif finding.startswith("E_FORGELINE_REQUIRED"):
            plan.append(
                "Restore the missing selected capability gate with its candidate-bound receipt."
            )
        else:
            plan.append(
                "Obtain human-confirmed intent approval and complete explicit forbidden behavior and gate fields."
            )
    return plan


def _promotion_core(
    spec: dict[str, Any],
    spec_source: Path,
    forge_source: Path,
    root: Path,
    digest: str,
    findings: list[str],
) -> dict[str, Any]:
    ready = not findings
    return {
        "schema": "factory.specforge.promotion-receipt.v1",
        "marker": "SPECFORGE_PROMOTION_READY"
        if ready
        else "SPECFORGE_PROMOTION_BLOCKED",
        "ok": ready,
        "action_summary": "Bind ForgeLine promotion to one approved SpecLine intent digest and only the explicitly selected capability gates; do not execute, release, or override a human.",
        "intent_sha256": digest,
        "obligation_count": len(spec["obligations"]),
        "required_gates": spec["required_gates"],
        "findings": findings,
        "repair_plan": _repair_plan(findings),
        "sources": {
            "specline": spec_source.relative_to(root).as_posix(),
            "forgeline": forge_source.relative_to(root).as_posix(),
        },
        "authority": {**AUTHORITY, "execution": False, "release": False},
        "claim_boundary": "Local topology and digest validation only; not proof that external SpecLine or ForgeLine ran, nor a release approval.",
    }


def verify_specforge_promotion(
    root: Path, spec_path: Path, forge_path: Path, out_path: Path
) -> dict[str, Any]:
    """Fail closed if ForgeLine tries to promote work outside an approved SpecLine packet."""
    root = Path(root).resolve()
    spec, spec_source = _read(root, spec_path)
    forge, forge_source = _read(root, forge_path)
    _validate_spec(spec)
    digest = _sha(spec["intent"])
    findings = _spec_findings(spec) + _forge_findings(spec, forge, digest)
    core = _promotion_core(spec, spec_source, forge_source, root, digest, findings)
    receipt = {**core, "receipt_sha256": _sha(core)}
    target = _output(root, out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {**receipt, "path": target.relative_to(root).as_posix()}
