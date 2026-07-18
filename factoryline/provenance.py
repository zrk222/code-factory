"""Shared machine-readable provenance envelope for FactoryLine itself."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import subprocess
import sys
from pathlib import Path

from . import __version__
from ._build_provenance import SOURCE_COMMIT


def _source_commit(module_dir: Path) -> str | None:
    source_root = module_dir.parent
    manifest = source_root / "pyproject.toml"
    if not (source_root / ".git").exists() or not manifest.exists():
        return None
    if 'name = "factoryline-code-factory"' not in manifest.read_text(encoding="utf-8"):
        return None
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=source_root, capture_output=True, text=True, timeout=3)
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=source_root,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except OSError:
        return None
    if result.returncode != 0 or dirty.returncode != 0 or dirty.stdout.strip():
        return None
    return result.stdout.strip()


def _build_hash(module_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(module_dir.rglob("*.py")):
        digest.update(path.relative_to(module_dir).as_posix().encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def provenance() -> dict:
    """Return package, source-commit, and build-hash provenance for this installation."""
    module_dir = Path(__file__).resolve().parent
    direct_url = None
    origin = "unknown"
    try:
        distribution = importlib.metadata.distribution("factoryline-code-factory")
        text = distribution.read_text("direct_url.json")
        if text:
            direct_url = json.loads(text).get("url")
            origin = "direct-url"
        else:
            origin = "site-packages"
    except importlib.metadata.PackageNotFoundError:
        origin = "source-tree"
    commit = _source_commit(module_dir) or SOURCE_COMMIT
    build_hash = _build_hash(module_dir)
    return {
        "schema": "factoryline.provenance.v1",
        "package": "factoryline-code-factory",
        "version": __version__,
        "source_commit": commit,
        "build_hash": build_hash,
        "install_origin": origin,
        "direct_url": direct_url,
        "python": sys.version.split()[0],
        "runtime": {"python": sys.version.split()[0], "implementation": sys.implementation.name},
        "receipt_schema": "factory.receipt.v2",
        "identity_complete": bool(commit and build_hash),
    }
