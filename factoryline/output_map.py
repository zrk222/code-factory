"""Deterministic Mermaid inventories for completed Code Factory starters."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Iterable


OUTPUT_MAP_SCHEMA = "factory.output-map.v1"
OUTPUT_MAP_MARKER = "CODE_FACTORY_OUTPUT_MAP_V1"
OUTPUT_MAP_RELATIVE_PATH = "docs/CODE_FACTORY_OUTPUT_MAP.md"


def _relative_path(value: str) -> str:
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("OUTPUT_MAP_PATH_INVALID")
    normalized = candidate.as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized:
        raise ValueError("OUTPUT_MAP_PATH_INVALID")
    return normalized


def _label(value: str) -> str:
    """Return a conservative Mermaid label for a root-relative artifact name."""
    return value.replace("\\", "/").replace('"', "'").replace("[", "(").replace("]", ")")


def _files(root: Path, expected_paths: Iterable[str]) -> list[str]:
    values = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }
    values.add(OUTPUT_MAP_RELATIVE_PATH)
    values.update(_relative_path(path) for path in expected_paths)
    return sorted(values)


def _mermaid(*, name: str, source_sha256: str, status: str, paths: list[str]) -> str:
    prefix = source_sha256[:12]
    lines = [
        "flowchart TD",
        f'    S["Bound source SHA-256: {prefix}"] --> O["{_label(name)} starter"]',
        f'    O --> B["Promotion: {_label(status)}"]',
    ]
    for index, path in enumerate(paths, 1):
        node = f"F{index:03d}"
        lines.append(f'    O --> {node}["{_label(path)}"]')
    lines.extend([
        "    classDef source fill:#dbeafe,stroke:#2563eb,color:#10233f",
        "    classDef output fill:#dcfce7,stroke:#16a34a,color:#10233f",
        "    classDef boundary fill:#fee2e2,stroke:#dc2626,color:#10233f",
        "    class S source",
        "    class O output",
        "    class B boundary",
    ])
    return "\n".join(lines)


def write_output_map(
    root: Path,
    *,
    name: str,
    source_sha256: str,
    status: str,
    expected_paths: Iterable[str] = (),
) -> dict[str, object]:
    """Write one complete, root-relative Mermaid output map and return its digest."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("OUTPUT_MAP_ROOT_NOT_FOUND")
    if len(source_sha256) != 64 or any(char not in "0123456789abcdef" for char in source_sha256):
        raise ValueError("OUTPUT_MAP_SOURCE_SHA256_INVALID")

    paths = _files(root, expected_paths)
    map_path = root / OUTPUT_MAP_RELATIVE_PATH
    map_path.parent.mkdir(parents=True, exist_ok=True)
    mermaid = _mermaid(name=name, source_sha256=source_sha256, status=status, paths=paths)
    map_path.write_text(
        "\n".join([
            "# Code Factory output map",
            "",
            f"Marker: `{OUTPUT_MAP_MARKER}`",
            "Runtime marker: `MCP_STDLIB_ONLY`",
            f"Schema: `{OUTPUT_MAP_SCHEMA}`",
            f"Starter: `{name}`",
            f"Source SHA-256: `{source_sha256}`",
            f"Promotion: **{status}**. The starter is blocked pending product-specific proof. This map is an output inventory, not a completion certificate.",
            "",
            "```mermaid",
            mermaid,
            "```",
            "",
            "## Generated files",
            "",
            *[f"- `{path}`" for path in paths],
            "",
            "## Optional sharing",
            "",
            "If this output map helped your team, you may choose to add this attribution to a public PR, README, or team message. Code Factory does not post it, edit other files, or send output data:",
            "",
            "```md",
            "[Built with Code Factory](https://github.com/zrk222/code-factory) — local-first, proof-first software workflows.",
            "```",
            "",
        ]),
        encoding="utf-8",
    )
    return {
        "schema": OUTPUT_MAP_SCHEMA,
        "marker": OUTPUT_MAP_MARKER,
        "markers": [OUTPUT_MAP_MARKER, "MCP_STDLIB_ONLY"],
        "path": OUTPUT_MAP_RELATIVE_PATH,
        "sha256": sha256(map_path.read_bytes()).hexdigest(),
        "file_count": len(paths),
        "files": paths,
    }
