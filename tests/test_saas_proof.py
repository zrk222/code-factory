import json
from pathlib import Path

import pytest

from factoryline.saas_proof import SaasProofError, saas_proof_projection, verify_saas_proof


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _contract() -> dict:
    return {
        "schema": "factory.saas-proof.contract.v1", "app_id": "demo",
        "provider": {"name": "any-oidc", "protocol": "oidc", "flow": "authorization_code_pkce", "issuer": "https://issuer.example", "audience": "demo-api", "pkce_required": True, "claims": {"subject": "sub", "tenant": "org_id", "roles": "roles"}},
        "promises": [{"id": "pro", "sku": "pro-monthly", "entitlement": "pro"}],
    }


def _evidence() -> dict:
    types = ["auth_success", "authorization_bound", "checkout_completed", "webhook_verified", "entitlement_granted", "feature_access"]
    events = []
    for sequence, event_type in enumerate(types, 1):
        events.append({"id": f"e{sequence}", "provider_event_id": f"p{sequence}", "sequence": sequence, "type": event_type, "subject": "u1", "tenant": "t1", "role": "member", "sku": "pro-monthly", "entitlement": "pro", "verified": True, "issuer": "https://issuer.example" if event_type == "auth_success" else None, "audience": "demo-api" if event_type == "auth_success" else None, "token_active": True if event_type == "auth_success" else None})
    return {"schema": "factory.saas-proof.evidence.v1", "app_id": "demo", "build_id": "b1", "events": events}


def test_provider_neutral_lifecycle_verifies_and_projects(tmp_path: Path):
    receipt = verify_saas_proof(tmp_path, _write(tmp_path / "contract.json", _contract()), _write(tmp_path / "evidence.json", _evidence()), Path(".factory/saas-proof/latest.json"))
    assert receipt["verdict"] == "verified"
    assert receipt["provider"]["name"] == "any-oidc"
    assert not any(receipt["authority"].values())
    projection = saas_proof_projection(tmp_path)
    assert projection["current_count"] == 1
    assert projection["invalid_count"] == 0


def test_missing_observation_and_stale_entitlement_block(tmp_path: Path):
    evidence = _evidence()
    evidence["events"] = [item for item in evidence["events"] if item["type"] != "webhook_verified"]
    evidence["events"].extend([
        {"id": "e7", "sequence": 7, "type": "refund", "subject": "u1", "tenant": "t1", "sku": "pro-monthly", "entitlement": "pro", "verified": True},
    ])
    receipt = verify_saas_proof(tmp_path, _write(tmp_path / "contract.json", _contract()), _write(tmp_path / "evidence.json", evidence), Path(".factory/saas-proof/latest.json"))
    assert receipt["verdict"] == "blocked"
    assert receipt["summary"]["unknown"] == 1
    assert {item["code"] for item in receipt["findings"]} >= {"SAAS_PROOF_STALE_ENTITLEMENT"}


def test_raw_tokens_and_non_pkce_contracts_fail_closed(tmp_path: Path):
    contract = _contract(); contract["provider"]["pkce_required"] = False
    with pytest.raises(SaasProofError) as error:
        verify_saas_proof(tmp_path, _write(tmp_path / "contract.json", contract), _write(tmp_path / "evidence.json", _evidence()), Path("out.json"))
    assert error.value.code == "SAAS_PROOF_PKCE_REQUIRED"
    evidence = _evidence(); evidence["access_token"] = "secret"
    with pytest.raises(SaasProofError) as error:
        verify_saas_proof(tmp_path, _write(tmp_path / "contract2.json", _contract()), _write(tmp_path / "evidence2.json", evidence), Path("out.json"))
    assert error.value.code == "SAAS_PROOF_SECRET_REJECTED"


def test_cross_tenant_journey_and_missing_build_binding_fail_closed(tmp_path: Path):
    evidence = _evidence()
    evidence["events"][-1]["tenant"] = "other-tenant"
    receipt = verify_saas_proof(tmp_path, _write(tmp_path / "contract.json", _contract()), _write(tmp_path / "evidence.json", evidence), Path("out.json"))
    assert receipt["verdict"] == "blocked"
    assert "SAAS_PROOF_CROSS_IDENTITY_OR_TENANT_JOURNEY" in {item["code"] for item in receipt["findings"]}

    missing_build = _evidence()
    del missing_build["build_id"]
    with pytest.raises(SaasProofError) as error:
        verify_saas_proof(tmp_path, _write(tmp_path / "contract2.json", _contract()), _write(tmp_path / "evidence2.json", missing_build), Path("out2.json"))
    assert error.value.code == "SAAS_PROOF_CONTRACT_INVALID"


def test_provider_issuer_must_be_absolute_https(tmp_path: Path):
    contract = _contract()
    contract["provider"]["issuer"] = "http://issuer.example"
    with pytest.raises(SaasProofError) as error:
        verify_saas_proof(tmp_path, _write(tmp_path / "contract.json", contract), _write(tmp_path / "evidence.json", _evidence()), Path("out.json"))
    assert error.value.code == "SAAS_PROOF_ISSUER_INVALID"
