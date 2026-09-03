import json
from pathlib import Path
from factoryline.review_integrity import verify_intent_diff, verify_receipt_freshness, verify_policy_pack

def w(p,v):p.write_text(json.dumps(v));return p
def test_three_senior_review_controls_fail_closed(tmp_path:Path):
    intent=w(tmp_path/'intent.json',{"schema":"factory.intent-diff-contract.v1","approved_paths":["src"],"forbidden_terms":["skip_auth"],"approval":{"origin":"human_confirmed"}})
    diff=w(tmp_path/'diff.json',{"schema":"factory.diff-manifest.v1","base_sha":"a","head_sha":"b","changed_paths":["src/a.py","infra/x.yml"],"added_text":"skip_auth = True"})
    assert verify_intent_diff(tmp_path,intent,diff,Path('.factory/intent.json'))['ok'] is False
    fresh=w(tmp_path/'fresh.json',{"schema":"factory.receipt-freshness-manifest.v1","current_commit":"b","environment_sha256":"e","now":"2026-09-03T12:00:00Z","receipts":[{"id":"r","commit":"a","environment_sha256":"e","expires_at":"2026-09-03T11:00:00Z","nonce":"n"},{"id":"r","commit":"b","environment_sha256":"x","expires_at":"2027","nonce":""}]})
    assert verify_receipt_freshness(tmp_path,fresh,Path('.factory/fresh.json'))['ok'] is False
    policy=w(tmp_path/'policy.json',{"schema":"factory.team-policy-pack.v1","owner":"platform","version":"1","approval":{"origin":"agent_proposed"},"rules":[{"id":"x","requirement":"","gate":"g"}]})
    assert verify_policy_pack(tmp_path,policy,Path('.factory/policy.json'))['ok'] is False
