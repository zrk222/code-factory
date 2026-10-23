from __future__ import annotations

from pathlib import Path


def test_operations_reference_reaches_shared_taxonomy_and_generated_junie(tmp_path):
    overlay = Path(__file__).parents[1]
    from factoryline import audit_taxonomy as audit
    from factoryline import junie_taxonomy as junie

    contract = audit.audit_taxonomy()["agent_usage_contract"]
    reference = contract["operations_reference"]
    assert reference["path"] == (
        "docs/AGENT_CONTRACTS.md#current-accuracy-operations-study249"
    )
    operations = (overlay / "docs" / "AGENT_CONTRACTS.md").read_text(encoding="utf-8")
    assert "33 true positives, 27 false positives" in operations
    assert "42.49-66.91%" in operations
    assert "76.74%" in operations and "common-claim measured gain was" in operations
    assert "32 of 33" in operations
    normalized = " ".join(operations.split())
    assert "human release owner separately validated" in normalized
    assert "prospectively frozen before prediction and labeling" in normalized
    assert "current bounded" in normalized
    assert "technical checks remain enforced" in normalized
    assert (
        "publication occurred" in normalized and "provider checks passed" in normalized
    )
    assert "at least 80%" in operations
    assert "133 core modules" in operations
    manifest = junie.junie_manifest(tmp_path)
    assert manifest["agent_usage_contract"] == contract
    for generated in (junie._guidance(), junie._junie_proof_agent_bytes()):
        assert reference["path"].encode() in generated
    assert audit.__file__.startswith(str(overlay))
    assert junie.__file__.startswith(str(overlay))


def test_current_owner_publication_hold_is_distinct_from_merge_and_historical_score():
    import json

    root = Path(__file__).parents[1]
    decision = json.loads(
        (root / "docs/evidence/owner-publication-hold251.json").read_text(
            encoding="utf-8"
        )
    )
    operations = (root / "docs/AGENT_CONTRACTS.md").read_text(encoding="utf-8")
    plan = (root / "plans/accuracy-efficiency174.md").read_text(encoding="utf-8")
    assert decision["publication"] == "HOLD"
    assert decision["current_measured_actionable_precision"] == 0.55
    assert decision["next_precision_target"] == 0.8
    assert decision["publish_dispatched"] is False
    assert decision["score_and_labels_unchanged"] is True
    assert (
        decision["pr255_merge"] == "authorized after required engineering checks pass"
    )
    assert "supersedes that publication authorization" in operations
    assert "hold publication until the next" in operations
    assert "Superseding publication hold" in plan
    assert "Do not dispatch the publish workflow" in operations
