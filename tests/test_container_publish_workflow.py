from __future__ import annotations

import re
from pathlib import Path


def test_container_publish_targets_exist_in_this_repository() -> None:
    repository = Path(__file__).resolve().parents[1]
    workflow = repository / ".github/workflows/github-packages.yml"
    source = workflow.read_text(encoding="utf-8")

    contexts = re.findall(r"^\s+context:\s*(\S+)\s*$", source, re.MULTILINE)
    dockerfiles = re.findall(r"^\s+file:\s*(\S+)\s*$", source, re.MULTILINE)

    assert contexts
    assert len(contexts) == len(dockerfiles)
    assert all((repository / context).is_dir() for context in contexts)
    assert all((repository / dockerfile).is_file() for dockerfile in dockerfiles)
