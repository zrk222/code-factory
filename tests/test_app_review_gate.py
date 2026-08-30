from pathlib import Path
import json

import pytest

from factoryline.app_review_gate import RULES, app_review_gate_projection, verify_app_review_readiness
from factoryline.revenueforge import RevenueForgeError


CANDIDATE = {"bundle_identifier": "com.example.app", "version": "1.2.0", "build_number": "42", "source_commit": "a" * 40}
CONDITIONAL = [key for key, _, mode, _, _ in RULES if mode == "conditional"]
ALWAYS = [key for key, _, mode, _, _ in RULES if mode == "always"]
APPLICABILITY = {key: {"status": "required", "reviewed_by": "Release Owner", "rationale": "This capability is present in the reviewed candidate."} for key in CONDITIONAL}


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _run(tmp_path: Path, checks: dict[str, object], *, observed: dict[str, str] | None = None):
    contract = _write(tmp_path / "contract.json", {"candidate": CANDIDATE, "applicability": APPLICABILITY})
    evidence = _write(tmp_path / "evidence.json", {"candidate": observed or CANDIDATE, "checks": checks})
    return verify_app_review_readiness(tmp_path, contract, evidence, Path(".factory/appforge/app-review.json"))


def test_exact_build_with_every_observation_is_ready(tmp_path: Path) -> None:
    receipt = _run(tmp_path, {key: True for key, _, _, _, _ in RULES})
    assert receipt["marker"] == "APP_REVIEW_READY"
    assert receipt["ok"] is True
    assert receipt["findings"] == []
    assert receipt["release_authority"]["app_review_submit"] is False
    assert all(value is False for value in receipt["authority"].values())
    assert len(receipt["receipt_sha256"]) == 64
    projection = app_review_gate_projection(tmp_path)
    assert projection["current_count"] == 1
    assert projection["latest"]["marker"] == "APP_REVIEW_READY"


@pytest.mark.parametrize("missing", [key for key, _, _, _, _ in RULES])
def test_every_rejection_derived_rule_fails_closed(tmp_path: Path, missing: str) -> None:
    checks = {key: True for key, _, _, _, _ in RULES}
    checks.pop(missing)
    receipt = _run(tmp_path, checks)
    assert receipt["marker"] == "APP_REVIEW_BLOCKED"
    assert receipt["ok"] is False
    assert [item["code"] for item in receipt["findings"]] == [f"APP_REVIEW_{missing.upper()}_UNPROVEN"]


@pytest.mark.parametrize("not_true", [False, None, 1, "true", [], {}])
def test_non_boolean_truth_cannot_bypass_purchase_gate(tmp_path: Path, not_true: object) -> None:
    checks: dict[str, object] = {key: True for key, _, _, _, _ in RULES}
    checks["physical_iphone_purchase"] = not_true
    receipt = _run(tmp_path, checks)
    assert any(item["code"] == "APP_REVIEW_PHYSICAL_IPHONE_PURCHASE_UNPROVEN" for item in receipt["findings"])


def test_evidence_from_another_build_is_rejected(tmp_path: Path) -> None:
    receipt = _run(tmp_path, {key: True for key, _, _, _, _ in RULES}, observed={**CANDIDATE, "build_number": "41"})
    assert receipt["marker"] == "APP_REVIEW_BLOCKED"
    assert receipt["findings"][0]["code"] == "APP_REVIEW_BUILD_BINDING_MISMATCH"


def test_malformed_candidate_is_refused(tmp_path: Path) -> None:
    contract = _write(tmp_path / "contract.json", {"candidate": {"bundle_identifier": "com.example.app"}, "applicability": APPLICABILITY})
    evidence = _write(tmp_path / "evidence.json", {"candidate": CANDIDATE, "checks": {}})
    with pytest.raises(RevenueForgeError) as error:
        verify_app_review_readiness(tmp_path, contract, evidence, Path("out.json"))
    assert error.value.code == "APP_REVIEW_CANDIDATE_INVALID"


def test_conditional_rule_cannot_disappear_by_omission(tmp_path: Path) -> None:
    contract = _write(tmp_path / "contract.json", {"candidate": CANDIDATE, "applicability": {}})
    evidence = _write(tmp_path / "evidence.json", {"candidate": CANDIDATE, "checks": {key: True for key in ALWAYS}})
    receipt = verify_app_review_readiness(tmp_path, contract, evidence, Path("gate.json"))
    assert receipt["marker"] == "APP_REVIEW_BLOCKED"
    assert sum(item["code"].endswith("_APPLICABILITY_UNREVIEWED") for item in receipt["findings"]) == len(CONDITIONAL)


def test_named_non_applicable_rule_is_preserved_in_receipt(tmp_path: Path) -> None:
    applicability = {**APPLICABILITY, CONDITIONAL[0]: {"status": "not_applicable", "reviewed_by": "Release Owner", "rationale": "The candidate has no account or authentication capability."}}
    contract = _write(tmp_path / "contract.json", {"candidate": CANDIDATE, "applicability": applicability})
    checks = {key: True for key, _, _, _, _ in RULES if key != CONDITIONAL[0]}
    evidence = _write(tmp_path / "evidence.json", {"candidate": CANDIDATE, "checks": checks})
    receipt = verify_app_review_readiness(tmp_path, contract, evidence, Path("gate.json"))
    assert receipt["marker"] == "APP_REVIEW_READY"
    assert receipt["not_applicable_rules"][0]["rule"] == CONDITIONAL[0]
