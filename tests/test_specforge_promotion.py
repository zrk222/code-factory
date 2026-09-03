import json
from pathlib import Path
from factoryline.specforge_promotion import verify_specforge_promotion

def test_specforge_promotion_fails_closed_on_intent_drift_and_missing_appforge_gates(tmp_path: Path):
    spec={"schema":"factory.specline.delivery-packet.v1","intent":{"mission":"ship proven app"},"approval":{"origin":"human_confirmed"},"obligations":[{"id":"screens","forbidden_behavior":"omit ipad","gate":"integrity"}]}
    sp=tmp_path/"spec.json";sp.write_text(json.dumps(spec)); fp=tmp_path/"forge.json";fp.write_text(json.dumps({"schema":"factory.forgeline.delivery-state.v1","intent_sha256":"wrong","state":"running","gates":{}}))
    receipt=verify_specforge_promotion(tmp_path,sp,fp,Path(".factory/specforge.json"))
    assert receipt["ok"] is False
    assert "E_FORGELINE_INTENT_DRIFT" in receipt["findings"]
    assert any(x.startswith("E_FORGELINE_REQUIRED_GATE_MISSING") for x in receipt["findings"])
