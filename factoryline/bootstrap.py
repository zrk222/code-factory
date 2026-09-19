"""Lightweight console-script bootstrap for the FactoryLine CLI.

The installed ``factory`` command is commonly probed for provenance before an
agent decides which workflow to run.  Importing the full command registry for
that probe is unnecessary and expensive, so this module keeps the version
path dependency-light and imports :mod:`factoryline.cli` only for real work.
"""

from __future__ import annotations

import json
import sys


def _emit_version(as_json: bool) -> int:
    """Print the same provenance envelope as the full CLI."""
    from .provenance import provenance

    payload = provenance()
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if as_json
        else f"factory {payload['version']}"
    )
    return 0


def main(argv=None) -> int:
    """Dispatch version probes without loading the 490-command registry."""
    values = list(sys.argv[1:] if argv is None else argv)
    if values and values[0] == "--version":
        return _emit_version("--json" in values)
    from .cli import main as cli_main

    return cli_main(values)


if __name__ == "__main__":
    raise SystemExit(main())
