from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from factoryline.intake_grill import confirm_intake, grill_intake
from factoryline.intake_parameters import (
    REQUIRED_AUDIT_LANES,
    IntakeParametersError,
    intake_parameters_status,
    seal_intake_parameters,
    verify_intake_parameters,
)


def _confirmation(root: Path) -> Path:
    prd = root / "mission.md"
    prd.write_text("# Mission\nBuild a Python CLI that reports a verified result for a developer.\n", encoding="utf-8")
    grill = grill_intake(prd, root, project="intake-demo")
    framework = next(item["id"] for item in grill["framework_shortlist"] if item["id"] == "python-service")
    confirmation = confirm_intake(
        root,
        Path(grill["path"]),
        framework,
        "The developer receives a deterministic verification result for the submitted local change.",
        "The CLI shows the result status and writes a receipt with the candidate hash for every required audit lane.",
        "local_only",
        "Rick Katz",
        "The local intake is bounded before any worker receives it.",
    )
    return Path(confirmation["path"])


def _request(root: Path, confirmation: Path, *, provenance: dict | None = None, **overrides) -> Path:
    request = {
        "schema": "factory.intake-parameters-request.v1",
        "intake_confirmation": confirmation.relative_to(root).as_posix(),
        "parameters": {
            "mode": "supervised",
            "risk": "medium",
            "budgets": {"max_iterations": 3, "max_wall_seconds": 300, "max_tokens": 12000, "max_cost_usd": 5.0},
            "scope_paths": ["factoryline", "tests"],
            "required_lanes": list(REQUIRED_AUDIT_LANES),
            "external_effects": "local_only",
        },
        "provenance": provenance or {key: {"origin": "human_confirmed", "source": "named human intake decision"} for key in ("mode", "risk", "budgets", "scope_paths", "required_lanes", "external_effects")},
        "approved_by": "Rick Katz",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat().replace("+00:00", "Z"),
        "rationale": "Keep the worker bounded to the confirmed local intent and complete audit set.",
    }
    for key, value in overrides.items():
        request["parameters"][key] = value
    path = root / "intake-request.json"
    path.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
    return path


def test_seal_and_verify_authoritative_envelope(tmp_path: Path):
    confirmation = _confirmation(tmp_path)
    request = _request(tmp_path, confirmation)
    receipt = seal_intake_parameters(tmp_path, request)
    assert receipt["status"] == "READY"
    assert sorted(receipt["authoritative_parameters"]) == ["budgets", "external_effects", "mode", "required_lanes", "risk", "scope_paths"]
    check = verify_intake_parameters(tmp_path, Path(receipt["path"]))
    assert check["valid"] is True
    assert check["authoritative"] is True
    assert check["marker"] == "INTAKE_PARAMETERS_VERIFIED"


def test_agent_proposals_are_advisory_and_never_authoritative(tmp_path: Path):
    confirmation = _confirmation(tmp_path)
    provenance = {key: {"origin": "human_confirmed", "source": "named human intake decision"} for key in ("mode", "risk", "budgets", "scope_paths", "required_lanes", "external_effects")}
    provenance["budgets"] = {"origin": "agent_proposed", "source": "worker recommendation for review"}
    request = _request(tmp_path, confirmation, provenance=provenance)
    receipt = seal_intake_parameters(tmp_path, request)
    assert receipt["status"] == "REVIEW_REQUIRED"
    assert receipt["advisory_parameters"] == ["budgets"]
    assert verify_intake_parameters(tmp_path, Path(receipt["path"]))["authoritative"] is False


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("required_lanes", list(REQUIRED_AUDIT_LANES[:-1]), "INTAKE_PARAMETERS_LANES_INVALID"),
        ("scope_paths", ["../outside"], "INTAKE_PARAMETERS_PATH_BOUNDARY"),
        ("budgets", {"max_iterations": 99, "max_wall_seconds": 300, "max_tokens": 12000, "max_cost_usd": 5.0}, "INTAKE_PARAMETERS_BUDGET_INVALID"),
        ("mode", "autonomous", "INTAKE_PARAMETERS_AUTONOMY_REJECTED"),
    ],
)
def test_invalid_or_unsafe_parameters_fail_closed(tmp_path: Path, field: str, value, code: str):
    confirmation = _confirmation(tmp_path)
    if field == "mode":
        provenance = {key: {"origin": "human_confirmed", "source": "named human intake decision"} for key in ("mode", "risk", "budgets", "scope_paths", "required_lanes", "external_effects")}
        provenance["mode"] = {"origin": "agent_proposed", "source": "worker recommendation for review"}
        request = _request(tmp_path, confirmation, provenance=provenance, **{field: value})
    else:
        request = _request(tmp_path, confirmation, **{field: value})
    with pytest.raises(IntakeParametersError) as exc:
        seal_intake_parameters(tmp_path, request)
    assert exc.value.code == code


def test_external_effects_must_match_confirmation(tmp_path: Path):
    confirmation = _confirmation(tmp_path)
    request = _request(tmp_path, confirmation, external_effects="human_controlled")
    with pytest.raises(IntakeParametersError) as exc:
        seal_intake_parameters(tmp_path, request)
    assert exc.value.code == "INTAKE_PARAMETERS_EXTERNAL_EFFECTS_MISMATCH"


def test_tamper_and_status_are_visible_without_execution(tmp_path: Path):
    confirmation = _confirmation(tmp_path)
    request = _request(tmp_path, confirmation)
    receipt = seal_intake_parameters(tmp_path, request)
    path = Path(receipt["path"])
    value = json.loads(path.read_text(encoding="utf-8"))
    value["parameters"]["risk"] = "low"
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    check = verify_intake_parameters(tmp_path, path)
    assert check["valid"] is False
    assert check["state"] == "BLOCKED"
    status = intake_parameters_status(tmp_path)
    assert status["state"] == "BLOCKED"
    assert status["invalid_count"] == 1
