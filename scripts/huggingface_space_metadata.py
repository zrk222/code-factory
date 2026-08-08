"""Validate the static Hugging Face Space card before a remote upload."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "factory.huggingface-space-metadata.v1"
REQUIRED = {"title", "sdk", "app_file", "short_description"}


def _front_matter(text: str) -> dict[str, str]:
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise ValueError("README.md must start with a Space-card YAML delimiter.")
    try:
        end = lines.index("---", 1)
    except ValueError as error:
        raise ValueError("README.md Space-card YAML must have a closing delimiter.") from error
    values: dict[str, str] = {}
    for line in lines[1:end]:
        if not line or line.lstrip().startswith("-") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip().strip('"\'')
    return values


def inspect(readme: Path) -> dict[str, Any]:
    try:
        metadata = _front_matter(readme.read_text(encoding="utf-8"))
        missing = sorted(key for key in REQUIRED if not metadata.get(key))
        short_description = metadata.get("short_description", "")
        errors = [f"missing required Space-card fields: {', '.join(missing)}"] if missing else []
        if metadata.get("sdk") != "static":
            errors.append("sdk must be static for this Space.")
        if metadata.get("app_file") != "index.html":
            errors.append("app_file must be index.html for this Space.")
        if len(short_description) > 60:
            errors.append("short_description must be 60 characters or fewer.")
    except (OSError, ValueError) as error:
        metadata, short_description, errors = {}, "", [str(error)]

    return {
        "schema": SCHEMA,
        "marker": "HUGGINGFACE_SPACE_METADATA_VALID" if not errors else "HUGGINGFACE_SPACE_METADATA_INVALID",
        "ok": not errors,
        "short_description_length": len(short_description),
        "errors": errors,
        "metadata": {key: metadata.get(key) for key in sorted(REQUIRED)},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a Hugging Face Space card without uploading it.")
    parser.add_argument("--readme", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = inspect(args.readme)
    print(json.dumps(result, sort_keys=True) if args.json else f"{result['marker']}: {result['errors']}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
