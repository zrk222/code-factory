from __future__ import annotations

import argparse
import json
import sys
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen


SCHEMA = "factory.jetbrains-marketplace-status.v1"


def _find_expected(updates: list[dict[str, Any]], expected_version: str | None) -> dict[str, Any] | None:
    if expected_version is None:
        return None
    return next((item for item in updates if item.get("version") == expected_version), None)


def _approved_and_listed(update: dict[str, Any] | None) -> bool:
    return bool(update and update.get("approve") is True and update.get("listed") is True)


def _value(item: dict[str, Any] | None, key: str) -> Any:
    return item.get(key) if item else None


def _marker_reason(
    pending_metadata: bool, expected_version: str | None, expected: dict[str, Any] | None
) -> tuple[str, str]:
    if pending_metadata:
        return "MARKETPLACE_UPDATE_PENDING", "plugin metadata is pending Marketplace approval"
    if expected_version and expected is None:
        return "MARKETPLACE_VERSION_MISSING", f"expected version {expected_version} is not present"
    if expected_version and not _approved_and_listed(expected):
        return "MARKETPLACE_VERSION_PENDING", f"expected version {expected_version} is not approved and listed"
    return "MARKETPLACE_UPDATE_CLEAR", "plugin metadata and expected version are approved"


def classify_status(
    plugin: dict[str, Any], updates: list[dict[str, Any]], *, expected_version: str | None = None
) -> dict[str, Any]:
    latest = next(iter(updates), None)
    pending_binary_update = plugin.get("hasUnapprovedUpdate") is True
    pending_metadata = plugin.get("approve") is not True or pending_binary_update
    expected = _find_expected(updates, expected_version)
    expected_clear = _approved_and_listed(expected)
    clear = not pending_metadata and (expected_version is None or expected_clear)
    marker, reason = _marker_reason(pending_metadata, expected_version, expected)

    return {
        "schema": SCHEMA,
        "plugin_id": plugin.get("id"),
        "name": plugin.get("name"),
        "downloads": plugin.get("downloads"),
        "pricing_model": plugin.get("pricingModel"),
        "plugin_approve": plugin.get("approve"),
        "has_unapproved_update": plugin.get("hasUnapprovedUpdate"),
        # A pending listing/metadata review and a queued binary update are
        # separate Marketplace states.  Only the latter occupies the update
        # submission slot.  Keep ``clear`` strict for status/read-back checks,
        # while exposing the narrower pre-upload decision explicitly.
        "upload_slot_clear": not pending_binary_update,
        "latest_version": _value(latest, "version"),
        "latest_approved": _value(latest, "approve"),
        "latest_listed": _value(latest, "listed"),
        "expected_version": expected_version,
        "expected_version_approved": _value(expected, "approve"),
        "expected_version_listed": _value(expected, "listed"),
        "clear": clear,
        "marker": marker,
        "reason": reason,
    }


def fetch_json(url: str) -> Any:
    with urlopen(url, timeout=30) as response:
        return json.load(response)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check public JetBrains Marketplace approval state.")
    parser.add_argument("--plugin-id", type=int, default=33009)
    parser.add_argument("--expected-version")
    parser.add_argument("--require-clear", action="store_true")
    parser.add_argument("--require-upload-slot", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        plugin = fetch_json(f"https://plugins.jetbrains.com/api/plugins/{args.plugin_id}")
        updates = fetch_json(f"https://plugins.jetbrains.com/api/plugins/{args.plugin_id}/updates?size=100")
        result = classify_status(plugin, updates, expected_version=args.expected_version)
    except (OSError, URLError, ValueError, json.JSONDecodeError) as error:
        result = {"schema": SCHEMA, "clear": False, "marker": "MARKETPLACE_STATUS_UNAVAILABLE", "reason": str(error)}
        print(json.dumps(result, sort_keys=True) if args.json else f"{result['marker']}: {result['reason']}")
        return 2

    print(json.dumps(result, sort_keys=True) if args.json else f"{result['marker']}: {result['reason']}")
    if args.require_clear and not result["clear"]:
        return 3
    if args.require_upload_slot and not result["upload_slot_clear"]:
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
