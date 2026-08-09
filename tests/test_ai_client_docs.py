from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "AI_CLIENTS.md"


def _fenced_json_blocks(text: str) -> list[dict[str, object]]:
    blocks = re.findall(r"```json\n(.*?)\n```", text, flags=re.DOTALL)
    return [json.loads(block) for block in blocks]


def test_cursor_and_opencode_examples_are_valid_and_use_local_mcp() -> None:
    text = DOC.read_text(encoding="utf-8")
    blocks = _fenced_json_blocks(text)

    cursor = next(block for block in blocks if "mcpServers" in block)
    cursor_server = cursor["mcpServers"]["code-factory"]
    assert cursor_server == {
        "command": "factory",
        "args": ["mcp", "serve", "--root", r"C:\work\my-mvp"],
    }

    opencode = next(block for block in blocks if "mcp" in block)
    opencode_server = opencode["mcp"]["code-factory"]
    assert opencode["$schema"] == "https://opencode.ai/config.json"
    assert opencode_server["type"] == "local"
    assert opencode_server["command"] == [
        "factory", "mcp", "serve", "--root", r"C:\work\my-mvp"
    ]
    assert opencode_server["enabled"] is True
    assert opencode_server["timeout"] == 5000


def test_ai_client_doc_keeps_connection_boundary_explicit() -> None:
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "stdio-only",
        "read-only",
        "do not start",
        "provider keys",
        "hosted MCP endpoint with OIDC",
        "Cursor-specific extension smoke test",
    ):
        assert required in text
