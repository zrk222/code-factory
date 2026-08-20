from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]
PLUGIN = ROOT / "plugins" / "code-factory-deepseek-harness"


def test_deepseek_harness_overlay_is_opt_in_local_mcp_only() -> None:
    overlay = (PLUGIN / "code-factory.cordis.yml").read_text(encoding="utf-8")

    assert "@deepseek-ai/dsh-mcp-client" in overlay
    assert "serverName: code_factory" in overlay
    assert "command: factory" in overlay
    assert "args: [mcp, serve, --root, .]" in overlay
    assert "cwd: !!js process.cwd()" in overlay
    assert "failOnStartupError: true" in overlay
    assert "reconnect:" in overlay
    assert "DEEPSEEK_API_KEY" not in overlay
    assert "token" not in overlay.lower()


def test_deepseek_harness_docs_keep_identity_and_execution_boundaries_explicit() -> None:
    readme = (PLUGIN / "README.md").read_text(encoding="utf-8")

    assert "dsh web --patch" in readme
    assert "factory mcp serve --root ." in readme
    assert "declared" in readme and "identifiers" in readme
    assert "not an execution grant" in readme
    assert "developer preview" in readme
    assert "dsh-plugin" in readme
