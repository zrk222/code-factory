"""Pin Code Factory's own size guard while allowing installed CLI usage."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

_SELF_SIZE_GUARD_SHA256 = (
    "542d8500ec436852c2d0862a7b8827fd1783a3f3407ca1a916ac8b2efb9b4084"
)


def is_code_factory_root(root: Path) -> bool:
    """Identify Code Factory by independent source, package or policy anchors."""
    if (root / "factoryline/architecture_health.py").is_file():
        return True
    try:
        document = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        document = {}
    project = document.get("project")
    if isinstance(project, dict) and project.get("name") == "factoryline-code-factory":
        return True
    try:
        default_policy = json.loads(
            (root / "architecture-policy.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return isinstance(default_policy, dict) and file_size_guard_is_pinned(
        default_policy.get("file_size_guard")
    )


def file_size_guard_is_pinned(guard: object) -> bool:
    """Check the exact required inventory and both ceilings against the pin."""
    if not isinstance(guard, dict) or guard.get("required") is not True:
        return False
    budgets = guard.get("files")
    paths = guard.get("required_paths")
    if (
        not isinstance(budgets, dict)
        or not budgets
        or not isinstance(paths, list)
        or any(not isinstance(path, str) for path in paths)
        or len(set(paths)) != len(paths)
        or set(paths) != set(budgets)
    ):
        return False
    try:
        inventory = sorted(
            (path, budgets[path]["max_lines"], budgets[path]["max_bytes"])
            for path in paths
        )
    except (KeyError, TypeError):
        return False
    digest = hashlib.sha256(repr(inventory).encode()).hexdigest()
    return digest == _SELF_SIZE_GUARD_SHA256


def default_policy_guard_is_pinned(root: Path) -> bool:
    """Require the checkout's canonical policy even when an override is used."""
    try:
        policy = json.loads(
            (root / "architecture-policy.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return isinstance(policy, dict) and file_size_guard_is_pinned(
        policy.get("file_size_guard")
    )
