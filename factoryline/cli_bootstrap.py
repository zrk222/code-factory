"""Lightweight installed FactoryLine command entry point."""

import sys
import time


_QUICK_HELP = """Code Factory - review your code and its evidence.

  Quick Python scan   factory scan --root . --static-only
  Deep review         factory scan --root .
  Visual workspace    factory studio --root .
  Scan options        factory scan --help
  Guidance            factory guide
  All commands        factory --help-all

Quick scan reads Python source without running your project.
Deep review shows applicable evidence and which checks remain INCOMPLETE.
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
        from .provenance import _emit_version

        return _emit_version("--json" in values)
    started = time.monotonic()
    from .ops_telemetry import _measure_phase, _phase_telemetry

    with _phase_telemetry(started):
        with _measure_phase("entrypoint_startup"):
            from .cli import main as cli_main
        return cli_main(values)
