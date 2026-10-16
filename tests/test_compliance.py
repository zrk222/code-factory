from __future__ import annotations

import pytest

from factoryline.compliance import ComplianceError, build_oscal_assessment

from factoryline.privacy import (
    PrivacyError,
    bbs_status,
    issue_bbs_credential,
    merkle_disclosure,
    verify_merkle_disclosure,
    zkvm_pilot_status,
)


@pytest.mark.parametrize("pack", ["nist-ssdf", "owasp-asvs", "soc2", "iso27001"])
def test_builtin_control_packs_emit_non_certifying_oscal_evidence(pack):
    result = build_oscal_assessment(pack, tenant_id="acme", evidence=[])
    assert result["schema"] == "factory.compliance.v1"
    assert (
        result["assessment-results"]["metadata"]["props"][-1]["value"]
        == "not-a-certification"
    )
    assert result["assessment_sha256"]


def test_customer_pack_accepts_reviewed_controls_and_maps_evidence():
    result = build_oscal_assessment(
        "customer",
        tenant_id="acme",
        custom_controls=[
            {"id": "ACME-1", "title": "Release approval", "evidence": ["approval"]}
        ],
        evidence=[{"control_ids": ["ACME-1"]}],
    )
    observation = result["assessment-results"]["results"][0]["observations"][0]
    assert observation["props"][0]["value"] == "satisfied"


def test_unknown_pack_is_rejected():
    with pytest.raises(ComplianceError) as error:
        build_oscal_assessment("unknown", tenant_id="acme", evidence=[])
    assert error.value.code == "E_CONTROL_PACK"


def test_merkle_disclosure_proves_one_leaf_without_disclosing_siblings():
    disclosure = merkle_disclosure(["a" * 64, "b" * 64, "c" * 64], "b" * 64)
    assert verify_merkle_disclosure(disclosure) is True
    assert "c" * 64 not in str(disclosure)
    disclosure["leaf"] = "d" * 64
    assert verify_merkle_disclosure(disclosure) is False


def test_merkle_rejects_unknown_leaf():
    with pytest.raises(PrivacyError) as error:
        merkle_disclosure(["a" * 64], "b" * 64)
    assert error.value.code == "E_LEAF_NOT_FOUND"


def test_optional_cryptographic_backends_fail_closed():
    assert bbs_status()["available"] is False
    assert zkvm_pilot_status()["available"] is False
    with pytest.raises(PrivacyError) as error:
        issue_bbs_credential()
    assert error.value.code == "E_BBS_UNAVAILABLE"
