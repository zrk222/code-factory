import json
import pytest
from factoryline.runtime_audit import runtime_audit_status
from factoryline.runtime_audit_common import canonical_bytes, sha256_bytes
from factoryline.runtime_audit_contract import LANES


@pytest.mark.parametrize("mutation", ["empty", "duplicate", "id", "state", "decision", "authority", "release", "malformed", "unknown"])
def test_rehashed_false_readiness_is_rejected(tmp_path, mutation):
    receipt = {"schema": "factory.runtime-audit-receipt.v1", "decision": "READY_FOR_HUMAN_REVIEW", "authority": "none", "release_approval": False,
               "lanes": [{"id": kind, "lane": kind, "state": "PASS"} for kind in LANES]}
    if mutation == "empty": receipt["lanes"] = []
    elif mutation == "duplicate": receipt["lanes"][-1] = receipt["lanes"][0]
    elif mutation == "id": receipt["lanes"][0]["id"] = ""
    elif mutation == "state": receipt["lanes"][0]["state"] = "UNKNOWN"
    elif mutation == "decision": receipt["lanes"][0]["state"] = "FAIL"
    elif mutation == "authority": receipt["authority"] = "release"
    elif mutation == "release": receipt["release_approval"] = True
    elif mutation == "unknown": receipt["lanes"][0]["lane"] = "other"
    else: receipt["lanes"][0] = None
    receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(receipt))
    path = tmp_path / ".factory/runtime-audits/run-test/runtime-audit-receipt.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(receipt))
    assert runtime_audit_status(tmp_path)["state"] == "INCOMPLETE"
