"""Lazy CLI boundary for privacy-safe telemetry inventory reconciliation."""

from __future__ import annotations

import json
from pathlib import Path


def add_parser(sub) -> None:
    """Register the read-only telemetry inventory command."""
    telemetry = sub.add_parser(
        "telemetry", help="reconcile local receipts, runs, traces, and meter ledgers"
    )
    telemetry_sub = telemetry.add_subparsers(dest="telemetry_cmd", required=True)
    inventory = telemetry_sub.add_parser(
        "inventory", help="emit a privacy-safe reconciled inventory"
    )
    inventory.add_argument("--root", default=".")
    inventory.add_argument("--json", action="store_true")


def run(a) -> int:
    """Emit the local inventory without execution, mutation, or publication authority."""
    from .telemetry import telemetry_inventory

    payload = telemetry_inventory(Path(a.root))
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0
