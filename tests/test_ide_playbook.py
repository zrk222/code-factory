from factoryline.ide_playbook import ide_playbook

def test_playbook_keeps_appforge_optional_and_external_agents_supervised():
    playbook = ide_playbook()
    assert playbook["default_path"] == ["start", "prove", "challenge", "trace", "handoff"]
    assert playbook["external_agent_ingress"]["protocols"] == ["A2A", "MCP"]
    assert playbook["external_agent_ingress"]["default_mode"] == "supervised"
    assert "AppForge activates only for explicit mobile delivery scope." in playbook["rules"]
