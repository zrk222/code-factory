from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "factoryline" / "hosted_console.html"


def test_console_is_responsive_read_only_and_handles_all_runtime_states():
    source = CONSOLE.read_text(encoding="utf-8")
    lowered = source.lower()
    assert '<meta name="viewport"' in source
    assert "@media (max-width: 560px)" in source
    assert 'id="empty"' in source
    assert 'id="loading"' in source
    assert 'id="error"' in source
    assert 'id="overview"' in source
    assert "CONTROL_CONSOLE_READ_ONLY" in source
    assert "method:" not in source
    assert all(term not in source for term in ["localStorage", "sessionStorage", "document.cookie"])
    assert all(term not in lowered for term in ["type=\"file\"", "deploy button", "release button"])


def test_console_uses_text_content_for_remote_values_and_clears_token_input():
    source = CONSOLE.read_text(encoding="utf-8")
    assert ".innerHTML" not in source
    assert 'document.getElementById("token").value = ""' in source
    assert "encodeURIComponent(tenant)" in source
    assert "Authorization: `Bearer ${token}`" in source
    assert "fetch(`/v1/admin/tenants/${encodeURIComponent(tenant)}/overview`" in source


def test_console_asset_is_declared_as_package_data():
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"hosted_console.html"' in project
