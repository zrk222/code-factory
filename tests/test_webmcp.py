from factoryline.webmcp import WEBMCP_TOOLS, webmcp_manifest


def test_webmcp_manifest_is_deterministic_read_only_and_progressive() -> None:
    first = webmcp_manifest()
    second = webmcp_manifest()
    assert first == second
    assert first["marker"] == "FACTORY_WEBMCP_PROGRESSIVE_READ_ONLY"
    assert first["spec_status"] == "draft-community-group-report"
    assert [item["name"] for item in first["tools"]] == [item["name"] for item in WEBMCP_TOOLS]
    assert "factory.saas_status" in [item["name"] for item in first["tools"]]
    assert "factory.oracle_firewall_status" in [item["name"] for item in first["tools"]]
    assert "factory.atomic_status" in [item["name"] for item in first["tools"]]
    assert "factory.appforge_oracle_status" in [item["name"] for item in first["tools"]]
    assert "factory.appforge_device_reality_status" in [item["name"] for item in first["tools"]]
    assert "factory.appforge_release_rehearsal_status" in [item["name"] for item in first["tools"]]
    assert "factory.appforge_native_surface_status" in [item["name"] for item in first["tools"]]
    assert "factory.appforge_surface_matrix_status" in [item["name"] for item in first["tools"]]
    assert "factory.appforge_storefront_story_status" in [item["name"] for item in first["tools"]]
    assert "factory.jetbrains_handshake_status" in [item["name"] for item in first["tools"]]
    assert all(item["inputSchema"]["additionalProperties"] is False for item in first["tools"])
    assert all(item["annotations"] == {"readOnlyHint": True, "untrustedContentHint": True} for item in first["tools"])
    assert all(value is False for value in first["authority"].values())
