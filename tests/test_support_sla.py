import json
from pathlib import Path


def test_support_sla_is_explicitly_proposed_until_activation_evidence_exists():
    policy = json.loads(
        (Path(__file__).parents[1] / "docs" / "SUPPORT_SLA_POLICY.json").read_text(
            encoding="utf-8"
        )
    )
    assert policy["schema"] == "factory.support-sla.v1"
    assert policy["status"] == "proposed"
    assert policy["effective"] is False
    assert policy["community"]["response_target"] is None
    assert policy["enterprise"]["contract_required"] is True
    assert len(policy["activation_evidence"]) >= 5
