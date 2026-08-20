"""Static contract checks for the Official MCP Registry release path."""
from __future__ import annotations

import json
from pathlib import Path

try:  # pragma: no cover - each branch is selected by the test runtime.
    import tomllib
except ModuleNotFoundError:  # Python 3.10 uses the declared test dependency.
    import tomli as tomllib

from factoryline import __version__


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "mcp" / "server.json"
WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
SERVER_NAME = "io.github.zrk222/code-factory"
MARKER = f"<!-- mcp-name: {SERVER_NAME} -->"


def _server() -> dict[str, object]:
    return json.loads(SERVER.read_text(encoding="utf-8"))


def test_registry_descriptor_is_bound_to_the_released_local_stdio_package() -> None:
    server = _server()
    package = server["packages"][0]

    assert server["$schema"] == "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
    assert server["name"] == SERVER_NAME
    assert server["version"] == __version__
    assert server["repository"] == {
        "url": "https://github.com/zrk222/code-factory",
        "source": "github",
        "id": "1293217553",
    }
    assert package["registryType"] == "pypi"
    assert package["registryBaseUrl"] == "https://pypi.org"
    assert package["identifier"] == "factoryline-code-factory"
    assert package["version"] == __version__
    assert package["transport"] == {"type": "stdio"}
    assert package["runtimeHint"] == "uvx"
    assert package["runtimeArguments"] == [
        {
            "type": "named",
            "name": "--from",
            "value": f"factoryline-code-factory=={__version__}",
        }
    ]
    assert [argument["value"] for argument in package["packageArguments"]] == ["factory", "mcp", "serve"]
    assert "environmentVariables" not in package


def test_pypi_long_description_source_and_registry_guide_carry_the_exact_marker() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "MCP_REGISTRY.md").read_text(encoding="utf-8")

    assert MARKER in readme
    assert MARKER in guide
    assert f"uvx --from factoryline-code-factory=={__version__} factory mcp serve" in guide
    for prohibited_claim in ("does not create a hosted", "add write authority", "access credentials"):
        assert prohibited_claim in guide


def test_registry_descriptor_is_shipped_with_the_source_distribution() -> None:
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert "include mcp/server.json" in manifest
    assert project["version"] == __version__


def test_registry_publication_is_post_pypi_oidc_and_fails_closed_on_drift() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "publish_mcp_registry:" in workflow
    assert "needs: [publish]" in workflow
    assert "id-token: write" in workflow
    assert "Validate release tag and MCP Registry metadata" in workflow
    assert "Wait for PyPI package and ownership marker" in workflow
    assert "MCP_REGISTRY_RELEASE_METADATA_VALID" in workflow
    assert "MCP_REGISTRY_METADATA_REJECTED" in workflow
    assert "PYPI_MCP_OWNERSHIP_MARKER_VERIFIED" in workflow
    assert "mcp-publisher login github-oidc" in workflow
    assert "mcp-publisher publish mcp/server.json" in workflow
    assert "mcp-publisher_linux_amd64.tar.gz" in workflow
    assert "sha256sum --check --strict --status" in workflow
    assert "secrets." not in workflow[workflow.index("publish_mcp_registry:"):]
