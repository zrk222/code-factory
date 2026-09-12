from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from factoryline.intake_grill import confirm_intake, grill_intake
from factoryline.intake_parameters import REQUIRED_AUDIT_LANES, seal_intake_parameters, verify_intake_binding


def _intake(root: Path, *, scope: list[str] | None = None, advisory: bool = False, mode: str = "supervised") -> tuple[Path, dict]:
    mission = root / "mission.md"
    mission.write_text("# Mission\nBuild a bounded local audit receipt.\n", encoding="utf-8")
    grilled = grill_intake(mission, root, project="admission-demo")
    confirmation = confirm_intake(
        root,
        Path(grilled["path"]),
        next(item["id"] for item in grilled["framework_shortlist"]),
        "The submitted change produces a deterministic audit receipt.",
        "The receipt cannot claim external execution or publication.",
        "local_only",
        "Rick Katz",
        "Admission is bounded before any worker receives it.",
    )
    request = {
        "schema": "factory.intake-parameters-request.v1",
        "intake_confirmation": Path(confirmation["path"]).relative_to(root).as_posix(),
        "parameters": {
            "mode": mode,
            "risk": "medium",
            "budgets": {"max_iterations": 3, "max_wall_seconds": 300, "max_tokens": 12000, "max_cost_usd": 5.0},
            "scope_paths": scope or ["factoryline", "tests"],
            "required_lanes": list(REQUIRED_AUDIT_LANES),
            "external_effects": "local_only",
        },
        "provenance": {key: {"origin": "human_confirmed", "source": "named human intake decision"} for key in ("mode", "risk", "budgets", "scope_paths", "required_lanes", "external_effects")},
        "approved_by": "Rick Katz",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat().replace("+00:00", "Z"),
        "rationale": "Keep the worker inside the confirmed local intent and audit set.",
    }
    if advisory:
        request["provenance"]["budgets"] = {"origin": "agent_proposed", "source": "worker recommendation for review"}
    request_path = root / "intake-request.json"
    request_path.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
    receipt = seal_intake_parameters(root, request_path)
    return Path(receipt["path"]), request


def test_matching_binding_requires_authoritative_receipt(tmp_path: Path):
    receipt_path, request = _intake(tmp_path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    result = verify_intake_binding(
        tmp_path,
        receipt_path,
        scope_paths=request["parameters"]["scope_paths"],
        required_lanes=list(REQUIRED_AUDIT_LANES),
        budgets=request["parameters"]["budgets"],
        mode="supervised",
        external_effects="local_only",
        expires_at=request["expires_at"],
        binding_sha256=receipt["parameter_sha256"],
    )
    assert result["ok"] is True
    assert result["marker"] == "INTAKE_BINDING_VERIFIED"


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"scope_paths": ["factoryline", "outside"]}, "E_INTAKE_BINDING_SCOPE_ESCAPE"),
        ({"budgets": {"max_wall_seconds": 301}}, "E_INTAKE_BINDING_BUDGET_INVALID"),
        ({"mode": "autonomous"}, "E_INTAKE_BINDING_MODE_MISMATCH"),
        ({"external_effects": "human_controlled"}, "E_INTAKE_BINDING_EXTERNAL_EFFECTS_MISMATCH"),
        ({"binding_sha256": "0" * 64}, "E_INTAKE_PARAMETER_DRIFT"),
    ],
)
def test_binding_rejects_drift(tmp_path: Path, kwargs: dict, code: str):
    receipt_path, request = _intake(tmp_path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    defaults = {
        "scope_paths": request["parameters"]["scope_paths"],
        "required_lanes": list(REQUIRED_AUDIT_LANES),
        "budgets": request["parameters"]["budgets"],
        "mode": "supervised",
        "external_effects": "local_only",
        "expires_at": request["expires_at"],
        "binding_sha256": receipt["parameter_sha256"],
    }
    defaults.update(kwargs)
    result = verify_intake_binding(tmp_path, receipt_path, **defaults)
    assert result["ok"] is False
    assert any(item["code"] == code for item in result["errors"])


def test_advisory_envelope_cannot_admit_work(tmp_path: Path):
    receipt_path, request = _intake(tmp_path, advisory=True)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    result = verify_intake_binding(
        tmp_path,
        receipt_path,
        scope_paths=request["parameters"]["scope_paths"],
        binding_sha256=receipt["parameter_sha256"],
    )
    assert result["ok"] is False
    assert any(item["code"] == "E_INTAKE_BINDING_ADVISORY" for item in result["errors"])
