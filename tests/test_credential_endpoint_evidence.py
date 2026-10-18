import copy
import json

import pytest

from factoryline import credential_endpoint_evidence as evidence
from factoryline.credential_publication_catalog import endpoint_publication


def _case(**overrides):
    sources = [{"path": "source.py", "sha256": "a" * 64}]
    bindings = {row["path"]: row["sha256"] for row in sources}
    finding = {
        "code": "SECURITY_HARDCODED_SECRET",
        "path": "source.py",
        "line": 2,
        "column": 4,
        "severity": "CRITICAL",
        "message": "original",
    }
    facts = {
        "schema": "factory.public-protocol-endpoint.v1",
        "disposition": "ENDPOINT_DECLARATION_ROLE_PROVEN",
        "flow_profile": "DECLARED_CLASS_MAY_FLOW",
        "runtime_assurance": "INCOMPLETE",
        "credential_safety": "UNASSESSED",
        "source_path": "source.py",
        "source_sha256": "a" * 64,
        "workspace_sources_sha256": evidence._digest(sorted(bindings.items())),
        "known_auth_uses": [],
        "linked_unknown_uses": [],
        "publication": endpoint_publication("https://appleid.apple.com/auth/token"),
        **overrides,
    }
    finding["facts"] = evidence.mint_endpoint_facts(facts, finding, bindings)
    return finding, sources, bindings


def test_native_marker_validates_only_current_bound_facts():
    finding, sources, bindings = _case()
    assert evidence.endpoint_binding(finding, sources, bindings)
    assert finding["severity"] == "CRITICAL"
    assert finding["facts"]["credential_safety"] == "UNASSESSED"


def test_json_roundtrip_and_plain_self_hashed_forgeries_have_no_native_marker():
    finding, sources, bindings = _case()
    document = json.loads(json.dumps(finding))
    document["facts"]["proof_facts_sha256"] = evidence._digest(document["facts"])
    assert not evidence.endpoint_binding(document, sources, bindings)
    assert not evidence.endpoint_binding(copy.deepcopy(finding), sources, bindings)
    assert not evidence.endpoint_binding(
        {**finding, "facts": copy.copy(finding["facts"])}, sources, bindings
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("path", "other.py"),
        ("line", 3),
        ("column", 5),
        ("code", "OTHER"),
        ("severity", "INFO"),
        ("message", "changed"),
    ],
)
def test_finding_identity_changes_invalidate_native_marker(field, value):
    finding, sources, bindings = _case()
    finding[field] = value
    assert not evidence.endpoint_binding(finding, sources, bindings)


def test_fact_or_attestation_mutation_cannot_keep_validation():
    finding, sources, bindings = _case()
    finding["facts"]["source_sha256"] = "b" * 64
    assert not evidence.endpoint_binding(finding, sources, bindings)
    with pytest.raises(AttributeError):
        finding["facts"]._attestation = ()
    with pytest.raises(ValueError):
        evidence._NativeEndpointFacts({}, finding, bindings, object())


def test_stale_or_expanded_source_inventory_is_rejected():
    finding, sources, bindings = _case()
    assert not evidence.endpoint_binding(finding, sources, {"source.py": "b" * 64})
    extra = {"path": "new_consumer.py", "sha256": "b" * 64}
    assert not evidence.endpoint_binding(
        finding, sources + [extra], {**bindings, extra["path"]: extra["sha256"]}
    )
    assert not evidence.endpoint_binding(finding, sources + sources, bindings)


@pytest.mark.parametrize(
    "overrides",
    [
        {"known_auth_uses": [{"slot": "password"}]},
        {"linked_unknown_uses": [{"reason": "unresolved_value_escape"}]},
        {"credential_safety": "SAFE"},
        {"runtime_assurance": "VERIFIED"},
    ],
)
def test_mixed_or_unknown_uses_and_inflated_claims_are_never_admitted(overrides):
    finding, sources, bindings = _case(**overrides)
    assert not evidence.endpoint_binding(finding, sources, bindings)
    assert finding["severity"] == "CRITICAL"


def test_publication_is_revalidated_even_with_native_marker(monkeypatch):
    finding, sources, bindings = _case()
    monkeypatch.setattr(evidence, "endpoint_publication", lambda value: None)
    assert not evidence.endpoint_binding(finding, sources, bindings)


def test_partition_roundtrip_rejection_retains_original_priority_and_message():
    from factoryline.review_integrity import partition_proven_primitive_observations

    finding, sources, _ = _case()
    core = {
        "sources": sources,
        "findings": [finding],
        "audit_coverage": {"complete": True},
    }
    partition_proven_primitive_observations(core)
    assert core["findings"] == []
    assert len(core["primitive_observations"]) == 1
    decoded = json.loads(json.dumps(core))
    partition_proven_primitive_observations(decoded)
    assert decoded["primitive_observations"] == []
    assert decoded["findings"][0]["severity"] == "CRITICAL"
    assert decoded["findings"][0]["message"] == "original"
    assert decoded["findings"][0]["facts"]["state"] == "INCOMPLETE"


@pytest.mark.parametrize("coverage", [None, {}, {"complete": False}, {"complete": 1}])
def test_incomplete_or_missing_capture_cannot_partition_endpoint(coverage):
    from factoryline.review_integrity import partition_proven_primitive_observations

    finding, sources, _ = _case()
    core = {"sources": sources, "findings": [finding]}
    if coverage is not None:
        core["audit_coverage"] = coverage
    partition_proven_primitive_observations(core)
    assert len(core["findings"]) == 1
    assert core["findings"][0]["severity"] == finding["severity"]
    assert not core["primitive_observations"]
