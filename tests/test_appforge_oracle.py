from __future__ import annotations

import json
from pathlib import Path

from factoryline.appforge_oracle import appforge_oracle_projection, verify_appforge_oracle_authority
from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract


AGENT = {"schema": "factory.agent-identity.v1", "subject": "builder-alpha", "provider": "local", "model": "model-a"}
CANDIDATE = {"bundle_identifier": "app.example.calm", "version": "1.0", "build_number": "42", "source_commit": "a" * 40}


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def _contract(root: Path) -> Path:
    original = root / "original.md"
    policy = root / "sources/apple-policy.md"
    original.write_text("The app must make subscription restore clear and safe.", encoding="utf-8")
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("Source-backed review policy snapshot.", encoding="utf-8")
    handoff = capture_intent_handoff(root, original, AGENT, "appforge-intake", Path(".factory/oracles/handoffs/appforge.json"))
    rule = lambda identifier, statement, **extra: {"id": identifier, "statement": statement, "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True, **extra}
    source = _write(root / "oracle-input.json", {
        "schema": "factory.oracle-contract-input.v1", "id": "appforge-review", "version": 1,
        "approved_by": "Release Owner", "approval_rationale": "The release owner checked user intent, policy source, and the candidate review gates.", "scope_paths": ["."], "handoff": handoff["path"],
        "sources": [{"id": "apple-policy", "origin": "trusted_source", "path": "sources/apple-policy.md"}],
        "requirements": [rule("restore", "Restore works for an entitled user.")],
        "forbidden_behaviors": [rule("double-charge", "Restore does not create a charge.")],
        "gates": [rule("accessibility", "Accessibility review is complete.", comparison="present", value=True)],
        "exceptions": [{"id": "offline-note", "statement": "Offline recovery needs a named future review.", "origin": "human_confirmed", "effect": "advisory", "source_id": "original-intent", "critical": False}],
        "negative_cases": [rule("expired", "Expired entitlements cannot restore access.")],
        "invariants": [rule("candidate", "Evidence stays bound to the exact candidate.")],
        "tests": [rule("restore-test", "Restore test must fail when expired access is accepted.", path="tests/test_restore.py")],
    })
    return root / seal_oracle_contract(root, source, Path(".factory/oracles/contracts/appforge.json"))["path"]


def _authority(root: Path, contract: Path, candidate: dict[str, str] = CANDIDATE) -> Path:
    return _write(root / "authority.json", {"schema": "factory.appforge.oracle-authority.v1", "contract_path": contract.relative_to(root).as_posix(), "candidate": candidate, "policy_sources": [{"source_id": "apple-policy"}], "human_reviewer": "Release Owner"})


def test_appforge_authority_binds_candidate_and_named_policy_source(tmp_path: Path) -> None:
    receipt = verify_appforge_oracle_authority(tmp_path, _authority(tmp_path, _contract(tmp_path)), candidate=CANDIDATE, out=Path(".factory/appforge/oracle-authority.json"))

    assert receipt["ok"] is True
    assert receipt["marker"] == "APPFORGE_ORACLE_AUTHORITY_READY"
    assert receipt["policy_sources"][0]["source_id"] == "apple-policy"
    assert appforge_oracle_projection(tmp_path)["current_count"] == 1


def test_appforge_authority_fails_closed_when_candidate_or_policy_authority_changes(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    receipt = verify_appforge_oracle_authority(tmp_path, _authority(tmp_path, contract), candidate={**CANDIDATE, "build_number": "43"})

    assert receipt["ok"] is False
    assert receipt["marker"] == "APPFORGE_ORACLE_AUTHORITY_BLOCKED"
    assert any(item["code"] == "APPFORGE_ORACLE_CANDIDATE_MISMATCH" for item in receipt["findings"])
