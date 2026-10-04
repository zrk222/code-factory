from __future__ import annotations

import hashlib

import pytest

from factoryline.contract import sha_of
from factoryline.deep_audit_io import bound_bytes, source_language
from factoryline.deep_audit_loop import deep_scan_projection
from factoryline.domain_ontology import domain_ontology_template
from factoryline.enterprise_receipts import dsse_pae
from factoryline.lifecycle_ledger import lifecycle_template
from factoryline.operations_control import operations_control_template
from factoryline.passport import mermaid_for
from factoryline.privacy import PrivacyError, merkle_root
from factoryline.proof_review_workflow import proof_review_projection
from factoryline.protocol import version_tuple
from factoryline.release_contract import release_readiness_projection
from factoryline.repair_loop import repair_loop_template
from factoryline.revenue_evidence import revenue_evidence_projection
from factoryline.repo_coordination import repo_coordination_template
from factoryline.service_boundaries import service_boundary_template
from factoryline.continuous_proof import continuous_proof_projection
from factoryline.judgment import judgment_projection


@pytest.mark.parametrize(
    "template",
    [
        domain_ontology_template,
        lifecycle_template,
        operations_control_template,
        repair_loop_template,
        repo_coordination_template,
        service_boundary_template,
    ],
)
def test_empty_templates_are_versioned_and_authority_free(template):
    value = template()

    assert value["schema"].startswith("factory.")
    assert value["claim_boundary"]
    assert all(flag is False for flag in value["authority"].values())


@pytest.mark.parametrize(
    "projection",
    [
        proof_review_projection,
        revenue_evidence_projection,
        continuous_proof_projection,
        judgment_projection,
        release_readiness_projection,
    ],
)
def test_empty_projections_report_no_local_evidence_or_authority(projection, tmp_path):
    value = projection(tmp_path)

    assert value["authority"]
    assert all(flag is False for flag in value["authority"].values())
    assert value.get("count", value.get("contract_count", 0)) == 0


def test_deep_scan_projection_marks_unrun_state_without_promoting_assurance(tmp_path):
    value, _ = deep_scan_projection(tmp_path)

    assert value["state"] == "NOT_RUN"
    assert value["analysis_complete"] is False
    assert value["authority"] == "none"


def test_sha_of_tracks_exact_bytes_and_absent_files(tmp_path):
    source = tmp_path / "source.py"
    source.write_bytes(b"value = 1\n")

    assert sha_of(source) == hashlib.sha256(source.read_bytes()).hexdigest()[:16]
    assert sha_of(tmp_path / "missing.py") == ""


def test_version_tuple_parses_release_components_and_rejects_invalid_versions():
    assert version_tuple("1.2.3") == (1, 2, 3)
    assert version_tuple("release 2-beta 4") == (2, 4)
    assert version_tuple("no digits") == (0,)


def test_merkle_root_is_order_independent_and_rejects_empty_commitments():
    assert merkle_root(["alpha", "beta"]) == merkle_root(["beta", "alpha"])
    assert merkle_root(["alpha", "beta"]) != merkle_root(["alpha", "gamma"])
    with pytest.raises(PrivacyError):
        merkle_root([])


def test_mermaid_for_emits_challenge_nodes_into_a_compact_proof_graph():
    graph = mermaid_for(
        {"challenges": [{"brick": "forge", "mutants_killed": 3, "mutants_total": 4}]}
    )

    assert "flowchart LR" in graph
    assert "forge: 3/4 rejected" in graph
    assert 'C1 --> P["Factory Passport"]' in graph


def test_dsse_pae_uses_utf8_byte_lengths_and_exact_payload_bytes():
    assert dsse_pae("t", b"x") == b"DSSEv1 1 t 1 x"
    encoded = dsse_pae("application/test", b"\x00\xff")
    assert encoded.startswith(b"DSSEv1 16 application/test 2 ")
    assert encoded.endswith(b"\x00\xff")


def test_source_language_classification_does_not_promote_unknown_formats():
    assert source_language("worker.py", b"print('ok')") == "python"
    assert source_language("launch.sh", b"#!/bin/sh\ntrue") == "shell"
    assert source_language("payload.bin", b"\x00\x01") == "unknown"


def test_bound_bytes_requires_matching_hash_and_workspace_containment(tmp_path):
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(b'{"state":"PASS"}')
    binding = {
        "path": "evidence.json",
        "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
    }

    assert bound_bytes(tmp_path, binding) == evidence.read_bytes()
    with pytest.raises(Exception, match="E_REPORT_DRIFT"):
        bound_bytes(tmp_path, {**binding, "sha256": "0" * 64})
    with pytest.raises(Exception, match="E_PATH_ESCAPE"):
        bound_bytes(tmp_path, {**binding, "path": "../outside.json"})


def test_proof_review_and_continuity_projections_stay_empty_without_receipts(tmp_path):
    review = proof_review_projection(tmp_path)
    continuity = continuous_proof_projection(tmp_path)
    revenue = revenue_evidence_projection(tmp_path)
    judgment = judgment_projection(tmp_path)
    readiness = release_readiness_projection(tmp_path)

    assert review["current_count"] == review["stale_count"] == 0
    assert continuity["current_count"] == continuity["stale_count"] == 0
    assert revenue["replay"]["count"] == 0
    assert judgment["status"] == "empty"
    assert readiness["contract_count"] == 0
