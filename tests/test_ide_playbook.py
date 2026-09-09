from factoryline.ide_playbook import ide_playbook

def test_playbook_keeps_appforge_optional_and_external_agents_supervised():
    playbook = ide_playbook()
    assert playbook["default_path"] == ["start", "prove", "challenge", "runtime_assurance", "trace", "handoff"]
    assert playbook["external_agent_ingress"]["protocols"] == ["A2A", "MCP"]
    assert playbook["external_agent_ingress"]["default_mode"] == "supervised"
    assert "Mission: current intent, scope, owner, and autonomy mode" in playbook["ui_contract"]["panels"]
    assert "risk_or_unknown" in playbook["ui_contract"]["action_card_required"]
    assert "Never ask for a rating or positive review." in playbook["proof_moment"]["limits"]
    assert "AppForge activates only for explicit mobile delivery scope." in playbook["rules"]
    assert any(item["id"] == "runtime_assurance" for item in playbook["capability_packs"])
    quality = next(item for item in playbook["capability_packs"] if item["id"] == "quality_harness")
    assert "full-stack" in quality["when"]
    assert "not certification" in quality["outcome"]
    assert "quality-harness template" in quality["next"]
    assert any("six human judgments" in item for item in playbook["external_agent_ingress"]["admission_rules"])
    decision = next(item for item in playbook["capability_packs"] if item["id"] == "release_decision")
    assert decision["next"] == "factory.release_decision"
    assert "provider state stays explicitly unobserved" in decision["outcome"]
    assert "A local release stop never proves provider rejection; inspect factory.release_decision before treating external state as known." in playbook["rules"]
    assert all(value is False for value in playbook["authority"].values())
