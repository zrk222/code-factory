"""Shared machine-readable provenance envelope for FactoryLine itself."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import subprocess
import sys
import time
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
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=source_root,
            capture_output=True,
            text=True,
            timeout=3,
        )
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=source_root,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
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
        "runtime": {
            "python": sys.version.split()[0],
            "implementation": sys.implementation.name,
        },
        "receipt_schema": "factory.receipt.v2",
        "identity_complete": bool(commit and build_hash),
    }


def _emit_version(as_json: bool) -> int:
    """Print the same provenance envelope as the full CLI."""
    payload = provenance()
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if as_json
        else f"factory {payload['version']}"
    )
    return 0


_QUICK_HELP = """Code Factory - review your code with less setup.

Start here:
  Scan my code       factory scan --root .
  Open dashboard     factory studio --root .
  Get guidance       factory guide

Next steps:
  More scan options  factory scan --help
  Check setup        factory doctor --strict --json
  All commands       factory --help-all

Scan reads eligible Python source without running your project.
Review findings, verify repairs with your tests, then rerun affected checks.
Keep pytest, mutation testing, CodeQL and Semgrep in your existing CI.
Missing evidence means INCOMPLETE; a scan is not release approval.
No adoption, signing keys or tenant configuration needed for a basic scan.
"""


def main(argv=None) -> int:
    """Show quick help and version probes without loading the command registry."""
    values = list(sys.argv[1:] if argv is None else argv)
    if values in (["--help"], ["-h"]):
        print(_QUICK_HELP, end="")
        return 0
    if values == ["--help-all"]:
        values = ["--help"]
    if values and values[0] == "--version":
        return _emit_version("--json" in values)
    started = time.monotonic()
    from .ops_telemetry import _measure_phase, _phase_telemetry

    with _phase_telemetry(started):
        with _measure_phase("entrypoint_startup"):
            from .cli import main as cli_main
        return cli_main(values)
