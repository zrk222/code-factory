from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.appforge_device_reality import (
    create_device_reality_intent_envelope,
    device_reality_projection,
    verify_device_reality,
)
from factoryline.cli import main
from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract
from factoryline.revenueforge import RevenueForgeError


CANDIDATE = {"bundle_identifier": "com.example.device", "version": "1.0.0", "build_number": "100", "source_commit": "a" * 40}
AGENT = {"schema": "factory.agent-identity.v1", "subject": "device-owner", "provider": "local", "model": "declared-model"}


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _authority(tmp_path: Path) -> Path:
    intent = tmp_path / "original-intent.md"
    policy = tmp_path / "sources" / "ios-policy.md"
    intent.write_text("A user can restore access without a charge.", encoding="utf-8")
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("Reviewed policy snapshot.", encoding="utf-8")
    handoff = capture_intent_handoff(tmp_path, intent, AGENT, "device-reality", Path(".factory/oracles/handoffs/device-reality.json"))
    rule = lambda identifier, statement, **extra: {"id": identifier, "statement": statement, "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True, **extra}
    contract = _write(tmp_path / "oracle-input.json", {
        "schema": "factory.oracle-contract-input.v1", "id": "device-reality", "version": 1,
        "approved_by": "Release Owner", "approval_rationale": "The owner approved the release intent and device journeys.",
        "scope_paths": ["."], "handoff": handoff["path"],
        "sources": [{"id": "ios-policy", "origin": "trusted_source", "path": "sources/ios-policy.md"}],
        "requirements": [rule("restore", "An eligible user can restore access.")],
        "forbidden_behaviors": [rule("no-charge", "Restore never creates a charge.")],
        "gates": [rule("device-proof", "A supervised device observation is present.", comparison="present", value=True)],
        "exceptions": [{"id": "future", "statement": "Future hardware review is advisory.", "origin": "human_confirmed", "effect": "advisory", "source_id": "original-intent", "critical": False}],
        "negative_cases": [rule("expired", "Expired access cannot restore.")],
        "invariants": [rule("candidate", "Evidence remains candidate-bound.")],
        "tests": [rule("restore-test", "The test fails if expired access restores.", path="tests/test_restore.py")],
    })
    sealed = seal_oracle_contract(tmp_path, contract, Path(".factory/oracles/contracts/device-reality.json"))
    return _write(tmp_path / "authority.json", {
        "schema": "factory.appforge.oracle-authority.v1", "contract_path": sealed["path"], "candidate": CANDIDATE,
        "policy_sources": [{"source_id": "ios-policy"}], "human_reviewer": "Release Owner",
    })


def _envelope(tmp_path: Path) -> dict[str, object]:
    design = tmp_path / "user-design.md"
    design.write_text("Use calm copy, a visible restore action, and a clear recovery state.", encoding="utf-8")
    return create_device_reality_intent_envelope(
        tmp_path, _authority(tmp_path), design,
        [{"id": "restore", "expected_outcome": "Eligible access is restored.", "forbidden_outcome": "No new purchase is created."}, {"id": "expired", "expected_outcome": "Expired access stays blocked.", "forbidden_outcome": "Expired access is restored."}],
        ["phone_harness", "manual_physical_device"], Path(".factory/appforge/device-reality-intent.json"),
    )


def _evidence(tmp_path: Path, envelope: dict[str, object]) -> Path:
    first = tmp_path / "captures" / "restore.png"
    second = tmp_path / "captures" / "expired.png"
    first.parent.mkdir(parents=True, exist_ok=True)
    first.write_bytes(b"real-device-restored")
    second.write_bytes(b"real-device-expired")
    return _write(tmp_path / "device-evidence.json", {
        "schema": "factory.appforge.device-reality-evidence.v1", "candidate": CANDIDATE,
        "intent_envelope_sha256": envelope["envelope_sha256"], "user_design_input_sha256": envelope["user_design_input"]["sha256"],
        "supervision": {"approved_by": "Release Owner", "approved_at": "2026-09-02T12:00:00Z", "human_present": True},
        "transport": {"kind": "phone_harness", "user_authorized": True},
        "captures": [
            {"journey": "restore", "path": "captures/restore.png", "sha256": _sha(first), "transport": "phone_harness", "expected_outcome": "Eligible access is restored.", "forbidden_outcome": "No new purchase is created.", "outcome": "passed"},
            {"journey": "expired", "path": "captures/expired.png", "sha256": _sha(second), "transport": "phone_harness", "expected_outcome": "Expired access stays blocked.", "forbidden_outcome": "Expired access is restored.", "outcome": "passed"},
        ],
    })


def test_device_reality_gate_requires_a_hash_sealed_intent_envelope_and_supervised_capture(tmp_path: Path) -> None:
    envelope = _envelope(tmp_path)
    receipt = verify_device_reality(tmp_path, Path(envelope["path"]), _evidence(tmp_path, envelope), Path(".factory/appforge/device-reality.json"))
    assert receipt["ok"] is True
    assert receipt["marker"] == "APPFORGE_DEVICE_REALITY_READY"
    assert receipt["transport"]["kind"] == "phone_harness"
    assert len(receipt["captures"]) == 2
    assert device_reality_projection(tmp_path)["latest"]["receipt_sha256"] == receipt["receipt_sha256"]


def test_device_reality_rejects_tampered_oracle_bound_intent_envelope(tmp_path: Path) -> None:
    envelope = _envelope(tmp_path)
    path = tmp_path / str(envelope["path"])
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["required_journeys"][0]["forbidden_outcome"] = "Worker rewrote the intended negative case."
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RevenueForgeError, match="intent envelope hash is invalid"):
        verify_device_reality(tmp_path, Path(envelope["path"]), _evidence(tmp_path, envelope), Path(".factory/appforge/blocked.json"))


def test_device_reality_fails_closed_on_scope_or_supervision_weakening(tmp_path: Path) -> None:
    envelope = _envelope(tmp_path)
    evidence = _evidence(tmp_path, envelope)
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    payload["supervision"]["human_present"] = False
    payload["captures"] = payload["captures"][:1]
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    receipt = verify_device_reality(tmp_path, Path(envelope["path"]), evidence, Path(".factory/appforge/blocked.json"))
    assert receipt["ok"] is False
    assert {item["code"] for item in receipt["findings"]} >= {"APPFORGE_DEVICE_REALITY_SUPERVISION_REQUIRED", "APPFORGE_DEVICE_REALITY_JOURNEYS_INCOMPLETE"}


def test_device_reality_cli_seals_then_verifies_only_workspace_scoped_inputs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    authority = _authority(tmp_path)
    design = tmp_path / "design.md"
    design.write_text("The restore action is visible.", encoding="utf-8")
    journeys = _write(tmp_path / "journeys.json", {"required_journeys": [{"id": "restore", "expected_outcome": "Eligible access is restored.", "forbidden_outcome": "No new purchase is created."}]})
    assert main(["revenue", "device-reality-intent", "--root", str(tmp_path), "--oracle-authority", str(authority.relative_to(tmp_path)), "--design-input", "design.md", "--journeys", str(journeys.relative_to(tmp_path)), "--transport", "manual_physical_device", "--out", ".factory/appforge/cli-intent.json", "--json"]) == 0
    envelope = json.loads(capsys.readouterr().out)
    capture = tmp_path / "capture.png"
    capture.write_bytes(b"manual-device-capture")
    evidence = _write(tmp_path / "cli-evidence.json", {"schema": "factory.appforge.device-reality-evidence.v1", "candidate": CANDIDATE, "intent_envelope_sha256": envelope["envelope_sha256"], "user_design_input_sha256": envelope["user_design_input"]["sha256"], "supervision": {"approved_by": "Release Owner", "approved_at": "2026-09-02T12:00:00Z", "human_present": True}, "transport": {"kind": "manual_physical_device", "user_authorized": True}, "captures": [{"journey": "restore", "path": "capture.png", "sha256": _sha(capture), "transport": "manual_physical_device", "expected_outcome": "Eligible access is restored.", "forbidden_outcome": "No new purchase is created.", "outcome": "passed"}]})
    assert main(["revenue", "device-reality-gate", "--root", str(tmp_path), "--intent-envelope", ".factory/appforge/cli-intent.json", "--evidence", str(evidence.relative_to(tmp_path)), "--out", ".factory/appforge/cli-receipt.json", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "APPFORGE_DEVICE_REALITY_READY"
