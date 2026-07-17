"""Constrained, read-only Git history adapter for repository context."""
from __future__ import annotations

from pathlib import Path
import subprocess


READ_ONLY_GIT_COMMANDS = frozenset({"ls-files", "log", "shortlog", "rev-parse"})


class RepositoryHistoryError(RuntimeError):
    pass


def git_lines(root: Path, *args: str) -> list[str]:
    """Run one allowlisted read-only Git query without shell evaluation."""
    if not args or args[0] not in READ_ONLY_GIT_COMMANDS:
        raise RepositoryHistoryError("Git query is not in the read-only allowlist")
    resolved = Path(root).resolve()
    result = subprocess.run(
        ["git", "-C", str(resolved), *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=15, check=False, shell=False,
    )
    if result.returncode:
        raise RepositoryHistoryError(result.stderr.strip() or "Git query failed")
    return [line for line in result.stdout.splitlines() if line.strip()]
