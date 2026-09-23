"""Lazy CLI boundary for the loopback-only Factory Studio server."""

from __future__ import annotations

import json
from pathlib import Path


def add_parser(sub) -> None:
    """Register the local Studio status and server commands."""
    studio = sub.add_parser("studio", help="run the loopback-only local target builder")
    studio.add_argument(
        "--root", default=".", help="directory beneath which Studio may create targets"
    )
    studio.add_argument(
        "--port", default=0, type=int, help="loopback port; 0 selects an available port"
    )
    studio.add_argument(
        "--no-browser",
        action="store_true",
        help="do not open the local URL automatically",
    )
    studio.add_argument(
        "--check",
        action="store_true",
        help="report the exact Studio boundary without starting a server",
    )
    studio.add_argument("--json", action="store_true")


def run(a) -> int:
    """Run or inspect Studio without granting network or deployment authority."""
    from .studio import StudioRequestError, serve_studio, studio_status

    if a.check:
        payload = studio_status(Path(a.root), a.port)
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("Factory Studio check")
            print(f"marker  : {payload['marker']}")
            print(
                f"listener: {payload['listener']['host']}:{payload['listener']['port']}"
            )
            print(f"root    : {payload['root']}")
        return 0
    try:
        print("marker: STUDIO_STARTED", flush=True)
        serve_studio(Path(a.root), port=a.port, open_browser=not a.no_browser)
    except StudioRequestError as exc:
        print(
            f"studio failed: {exc.code}: {exc.message}", file=__import__("sys").stderr
        )
        return 2
    except OSError as exc:
        print(f"studio failed: LISTENER_ERROR: {exc}", file=__import__("sys").stderr)
        return 1
    return 0
