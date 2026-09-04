from datetime import datetime, timedelta, timezone
from pathlib import Path
import json

import pytest

from factoryline.deep_audit_contract import PLAN_SCHEMA, PLAN_TYPE, verify_deep_audit_plan
from factoryline.deep_audit_io import digest
from factoryline.enterprise_receipts import generate_key_material, sign_payload, EnterpriseReceiptError
from factoryline.runtime_audit_common import RuntimeAuditError, sha256_bytes


def fixture(tmp_path, mutate=lambda p: None):
    bindings = {}
    for name, raw in (("app.py", b"one\ntwo"), ("scan.json", b'{"scan":1}'), ("canary.json", b'{"scan":2}')):
        (tmp_path/name).write_bytes(raw)
        bindings[name] = {"path": name, "sha256": sha256_bytes(raw)}
    sources = [{**bindings["app.py"], "bytes": 7}]
    now = datetime.now(timezone.utc)
    plan = {"schema": PLAN_SCHEMA, "id": "audit", "candidate_sha256": digest(sources), "issued_at": (now-timedelta(minutes=1)).isoformat(),
            "expires_at": (now+timedelta(hours=1)).isoformat(), "sources": sources,
            "analyzers": [{"id": "s", "driver": "Example", "version": "1", "report": bindings["scan.json"], "canary_report": bindings["canary.json"]}],
            "rules": [{"id": "r", "obligation_id": "no-leak", "category": "memory", "severity": "high", "aliases": [{"analyzer_id": "s", "rule_id": "leak"}],
                       "max_new": 0, "max_total": 0, "min_trace_steps": 2, "require_source_sink": True, "allowed_suppressions": [], "origin": "human_confirmed",
                       "remediation": "Close owned resources", "consequence": "Retained memory"}],
            "canaries": [{"id": "c", "analyzer_id": "s", "rule_id": "leak", "fingerprint_sha256": "a"*64}]}
    mutate(plan)
    material = generate_key_material(out_dir=tmp_path/"keys", keyid="owner", identity="owner@example.test", issuer="https://issuer.example.test")
    envelope = sign_payload(plan, payload_type=PLAN_TYPE, private_key_path=Path(material["private_key"]), keyid=material["keyid"], identity=material["identity"], issuer=material["issuer"])
    path = tmp_path/"plan.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    trust = Path(material["trust_root"])
    return path, trust, sha256_bytes(trust.read_bytes()), tmp_path


def test_signature_sources_and_policy_are_bound(tmp_path):
    args = fixture(tmp_path)
    checked = verify_deep_audit_plan(*args)
    assert checked["authority"] == "none"
    assert len(checked["ruleset_sha256"]) == 64
    assert checked["source_hashes"]["app.py"] == sha256_bytes(b"one\ntwo")
    (tmp_path/"scan.json").write_text("tampered")
    with pytest.raises(RuntimeAuditError, match="E_REPORT_DRIFT"):
        verify_deep_audit_plan(*args)


@pytest.mark.parametrize("mutate,code", [
    (lambda p: p["rules"][0].update(origin="agent_proposed"), "E_RULE_AUTHORITY"),
    (lambda p: p["rules"][0].update(origin="observed_production"), "E_RULE_AUTHORITY"),
    (lambda p: p["rules"][0].update(max_new=True), "E_FIELD"),
    (lambda p: p.update(candidate_sha256="b"*64), "E_CANDIDATE_DRIFT"),
    (lambda p: p.update(canaries=[]), "E_PLAN_FIELDS"),
    (lambda p: p["canaries"][0].update(rule_id="unknown"), "E_CANARY_POLICY"),
    (lambda p: p["analyzers"][0].update(canary_report=p["analyzers"][0]["report"]), "E_DUPLICATE_ID"),
    (lambda p: p.update(expires_at="2000-01-01T00:00:00+00:00"), "E_PLAN_EXPIRED"),
    (lambda p: p.update(issued_at="2020-01-01T00:00:00"), "E_TIME"),
    (lambda p: p.update(unapproved_exception=True), "E_PLAN_FIELDS"),
])
def test_signed_bad_contract_is_rejected(tmp_path, mutate, code):
    args = fixture(tmp_path, mutate)
    with pytest.raises(RuntimeAuditError, match=code):
        verify_deep_audit_plan(*args)


def test_wrong_pin_and_forged_signature(tmp_path):
    path, trust, pin, root = fixture(tmp_path)
    with pytest.raises(RuntimeAuditError, match="E_TRUST_ROOT_DRIFT"):
        verify_deep_audit_plan(path, trust, "0"*64, root)
    envelope = json.loads(path.read_text())
    envelope["signatures"][0]["sig"] = "AAAA"
    path.write_text(json.dumps(envelope))
    with pytest.raises((EnterpriseReceiptError, RuntimeAuditError)):
        verify_deep_audit_plan(path, trust, pin, root)


def test_verified_contract_drives_real_report_normalization(tmp_path):
    from test_deep_audit_sarif import report
    from factoryline.deep_audit_sarif import normalize_sarif

    def bind_reports(plan):
        for key, name in (("report", "scan.json"), ("canary_report", "canary.json")):
            payload = report()
            result = payload["runs"][0]["results"][0]
            result["ruleId"] = "leak"
            payload["runs"][0]["tool"]["driver"]["rules"][0]["id"] = "leak"
            result["partialFingerprints"]["primary/v1"] = key
            raw = json.dumps(payload).encode()
            (tmp_path/name).write_bytes(raw)
            plan["analyzers"][0][key]["sha256"] = sha256_bytes(raw)
        plan["canaries"][0]["fingerprint_sha256"] = digest({"partialFingerprints:primary/v1": "canary_report"})

    verified = verify_deep_audit_plan(*fixture(tmp_path, bind_reports))
    analyzer = verified["plan"]["analyzers"][0]
    target = normalize_sarif(tmp_path, analyzer["report"], analyzer, verified["source_hashes"])
    canary = normalize_sarif(tmp_path, analyzer["canary_report"], analyzer, verified["source_hashes"])
    assert target["findings"][0]["rule_id"] == "leak"
    assert canary["findings"][0]["native_fingerprint_sha256"] == verified["plan"]["canaries"][0]["fingerprint_sha256"]
    assert target["authority"] == "none"
