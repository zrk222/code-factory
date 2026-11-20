"""Lightweight installed FactoryLine command entry point."""

import sys
import time


_QUICK_HELP = """Code Factory - review your code and its evidence.

Start here:
  Scan my code       factory scan --root .
  Python checks only factory scan --static-only --root .
  Open dashboard     factory studio --root .
  Get guidance       factory guide

Next steps:
  More scan options  factory scan --help
  Check setup        factory doctor --strict --json
  All commands       factory --help-all

Default scan includes applicable checks and authorized configured workers.
Use --static-only for Python source checks without workers.
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
        if "--json" not in values:
            from . import __version__

            print(f"factory {__version__}")
            return 0
        from .provenance import _emit_version

        return _emit_version("--json" in values)
    started = time.monotonic()
    from .ops_telemetry import _measure_phase, _phase_telemetry

    with _phase_telemetry(started):
        with _measure_phase("entrypoint_startup"):
            from .cli import main as cli_main
        return cli_main(values)
