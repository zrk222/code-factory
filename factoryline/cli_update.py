"""Lazy CLI boundary for local Code Factory update notices."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def add_parser(sub: argparse._SubParsersAction) -> None:
    """Register the read-only update-check command."""
    parser = sub.add_parser(
        "update", help="check a local release manifest for an available update"
    )
    parser.add_argument("--manifest", default=".factory/update-manifest.json")
    parser.add_argument("--installed-version")
    parser.add_argument("--channel", default="stable")
    parser.add_argument("--json", action="store_true")


def run(args: argparse.Namespace) -> int:
    """Compare the installed version with local release metadata."""
    from . import __version__
    from .update_notifier import UpdateNotifierError, check_for_update, read_manifest

    try:
        notice = check_for_update(
            args.installed_version or __version__,
            read_manifest(Path(args.manifest)),
            channel=args.channel,
        )
    except (UpdateNotifierError, OSError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "schema": "factory.update-notice-error.v1",
                    "marker": "UPDATE_CHECK_REFUSED",
                    "message": str(exc),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    print(
        json.dumps(notice, indent=2, sort_keys=True) if args.json else notice["marker"]
    )
    return 0
