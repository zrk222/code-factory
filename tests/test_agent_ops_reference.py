from __future__ import annotations

from pathlib import Path


def test_operations_reference_reaches_shared_taxonomy_and_generated_junie(tmp_path):
    overlay = Path(__file__).parents[1]
    from factoryline import audit_taxonomy as audit
    from factoryline import junie_taxonomy as junie

    contract = audit.audit_taxonomy()["agent_usage_contract"]
    reference = contract["operations_reference"]
    assert reference["path"] == ("docs/AGENT_CONTRACTS.md#current-audit-operations")
    operations = (overlay / "docs" / "AGENT_CONTRACTS.md").read_text(encoding="utf-8")
    assert "publication hold" in operations
    assert "133 core modules" in operations
    assert (
        "Unsupported" in operations
        and "parser, source, and analysis errors" in operations
    )
    assert "Preserve original diagnostics and severity" in operations
    manifest = junie.junie_manifest(tmp_path)
    assert manifest["agent_usage_contract"] == contract
    for generated in (junie._guidance(), junie._junie_proof_agent_bytes()):
        assert reference["path"].encode() in generated
    assert audit.__file__.startswith(str(overlay))
    assert junie.__file__.startswith(str(overlay))
