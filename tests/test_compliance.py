from __future__ import annotations

import pytest

from factoryline.compliance import ComplianceError, CONTROL_PACKS, build_oscal_assessment


@pytest.mark.parametrize("pack", ["nist-ssdf", "owasp-asvs", "soc2", "iso27001"])
def test_builtin_control_packs_emit_non_certifying_oscal_evidence(pack):
    result = build_oscal_assessment(pack, tenant_id="acme", evidence=[])
    assert result["schema"] == "factory.compliance.v1"
    assert result["assessment-results"]["metadata"]["props"][-1]["value"] == "not-a-certification"
    assert result["assessment_sha256"]


def test_customer_pack_accepts_reviewed_controls_and_maps_evidence():
    result = build_oscal_assessment(
        "customer",
        tenant_id="acme",
        custom_controls=[{"id": "ACME-1", "title": "Release approval", "evidence": ["approval"]}],
        evidence=[{"control_ids": ["ACME-1"]}],
    )
    observation = result["assessment-results"]["results"][0]["observations"][0]
    assert observation["props"][0]["value"] == "satisfied"


def test_unknown_pack_is_rejected():
    with pytest.raises(ComplianceError) as error:
        build_oscal_assessment("unknown", tenant_id="acme", evidence=[])
    assert error.value.code == "E_CONTROL_PACK"

