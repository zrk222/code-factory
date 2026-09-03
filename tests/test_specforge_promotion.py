import json
from pathlib import Path
from factoryline.specforge_promotion import verify_specforge_promotion

def test_specforge_promotion_fails_closed_on_intent_drift_and_missing_selected_gates(tmp_path: Path):
    spec={"schema":"factory.specline.delivery-packet.v1","intent":{"mission":"ship proven app"},"approval":{"origin":"human_confirmed"},"obligations":[{"id":"tests","forbidden_behavior":"weaken oracle","gate":"oracle_firewall"}],"required_gates":["oracle_firewall","independent_challenge"]}
    sp=tmp_path/"spec.json";sp.write_text(json.dumps(spec)); fp=tmp_path/"forge.json";fp.write_text(json.dumps({"schema":"factory.forgeline.delivery-state.v1","intent_sha256":"wrong","state":"running","gates":{}}))
    receipt=verify_specforge_promotion(tmp_path,sp,fp,Path(".factory/specforge.json"))
    assert receipt["ok"] is False
    assert "E_FORGELINE_INTENT_DRIFT" in receipt["findings"]
    assert any(x.startswith("E_FORGELINE_REQUIRED_GATE_MISSING") for x in receipt["findings"])

def test_specforge_promotion_only_requires_appforge_when_spec_selects_it(tmp_path: Path):
    spec={"schema":"factory.specline.delivery-packet.v1","intent":{"mission":"review code"},"approval":{"origin":"human_confirmed"},"obligations":[{"id":"proof","forbidden_behavior":"hollow test","gate":"first_proof"}],"required_gates":["first_proof","oracle_firewall"]}; sp=tmp_path/"spec.json";sp.write_text(json.dumps(spec))
    from factoryline.specforge_promotion import _sha
    fp=tmp_path/"forge.json";fp.write_text(json.dumps({"schema":"factory.forgeline.delivery-state.v1","intent_sha256":_sha(spec["intent"]),"state":"verified","gates":{"first_proof":True,"oracle_firewall":True}}))
    assert verify_specforge_promotion(tmp_path,sp,fp,Path(".factory/ready.json"))["ok"] is True
