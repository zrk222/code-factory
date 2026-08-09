import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_mcp_registry_manifest_is_pypi_stdio_and_matches_release() -> None:
    manifest = json.loads((ROOT / ".mcp" / "server.json").read_text(encoding="utf-8"))
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert manifest["name"] == "io.github.zrk222/code-factory"
    assert manifest["version"] == "0.28.0"
    assert 'version = "0.28.0"' in project
    package = manifest["packages"][0]
    assert package["registryType"] == "pypi"
    assert package["identifier"] == "factoryline-code-factory"
    assert package["version"] == manifest["version"]
    assert package["runtimeHint"] == "uvx"
    assert package["transport"] == {"type": "stdio"}
    assert [argument["value"] for argument in package["runtimeArguments"]] == ["factory"]
    assert [argument["value"] for argument in package["packageArguments"]] == ["mcp", "serve"]


def test_mcp_registry_ownership_marker_is_exactly_once() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    marker = "<!-- mcp-name: io.github.zrk222/code-factory -->"
    assert readme.count(marker) == 1
