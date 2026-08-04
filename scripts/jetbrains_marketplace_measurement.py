"""Report observed JetBrains Marketplace download movement without invented conversion data."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen


BASELINE_SCHEMA = "factory.jetbrains-marketplace-baseline.v1"
MEASUREMENT_SCHEMA = "factory.jetbrains-marketplace-measurement.v1"


class BaselineError(ValueError):
    """Raised when the checked-in Marketplace baseline is not usable."""


def load_baseline(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BaselineError(f"BASELINE_UNREADABLE: {error}") from error

    if payload.get("schema") != BASELINE_SCHEMA:
        raise BaselineError("BASELINE_SCHEMA_INVALID")
    if not isinstance(payload.get("plugin_id"), int) or payload["plugin_id"] <= 0:
        raise BaselineError("BASELINE_PLUGIN_ID_INVALID")
    if not isinstance(payload.get("downloads"), int) or payload["downloads"] < 0:
        raise BaselineError("BASELINE_DOWNLOADS_INVALID")
    return payload


def fetch_json(url: str) -> Any:
    with urlopen(url, timeout=30) as response:
        return json.load(response)


def build_measurement(baseline: dict[str, Any], plugin: dict[str, Any]) -> dict[str, Any]:
    current_downloads = plugin.get("downloads")
    if not isinstance(current_downloads, int) or current_downloads < 0:
        raise BaselineError("MARKETPLACE_DOWNLOADS_UNAVAILABLE")

    delta = current_downloads - baseline["downloads"]
    return {
        "schema": MEASUREMENT_SCHEMA,
        "plugin_id": baseline["plugin_id"],
        "baseline": {
            "recorded_at": baseline.get("recorded_at"),
            "downloads": baseline["downloads"],
            "listed_version": baseline.get("listed_version"),
        },
        "current": {
            "downloads": current_downloads,
            "listed_version": plugin.get("version"),
            "pricing_model": plugin.get("pricingModel"),
            "approved": plugin.get("approve") is True,
            "has_unapproved_update": plugin.get("hasUnapprovedUpdate") is True,
        },
        "download_delta": delta,
        "download_delta_state": "observed" if delta >= 0 else "source_regression_review_required",
        "conversion_rate": None,
        "conversion_rate_state": "unavailable_without_marketplace_impressions_or_page_views",
        "causal_uplift": None,
        "causal_uplift_state": "unavailable_without_a_controlled_experiment_or_attribution_data",
        "markers": [
            "MARKETPLACE_DOWNLOAD_DELTA_OBSERVED",
            "MARKETPLACE_CONVERSION_NOT_INFERRED",
            "MARKETPLACE_CAUSAL_UPLIFT_NOT_INFERRED",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare a checked-in JetBrains Marketplace baseline with the public plugin record."
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("docs/JETBRAINS_MARKETPLACE_MEASUREMENT.json"),
        help="JSON baseline captured from the public Marketplace API.",
    )
    parser.add_argument("--plugin-id", type=int, default=None, help="Must match the baseline plugin ID when supplied.")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable measurement.")
    args = parser.parse_args(argv)

    try:
        baseline = load_baseline(args.baseline)
        plugin_id = args.plugin_id or baseline["plugin_id"]
        if plugin_id != baseline["plugin_id"]:
            raise BaselineError("BASELINE_PLUGIN_ID_MISMATCH")
        plugin = fetch_json(f"https://plugins.jetbrains.com/api/plugins/{plugin_id}")
        measurement = build_measurement(baseline, plugin)
    except (BaselineError, OSError, URLError, ValueError, json.JSONDecodeError) as error:
        result = {
            "schema": MEASUREMENT_SCHEMA,
            "measurable": False,
            "marker": "MARKETPLACE_MEASUREMENT_UNAVAILABLE",
            "reason": str(error),
        }
        print(json.dumps(result, sort_keys=True) if args.json else f"{result['marker']}: {result['reason']}")
        return 2

    print(json.dumps(measurement, sort_keys=True) if args.json else (
        f"Observed download delta: {measurement['download_delta']} "
        f"(baseline {measurement['baseline']['downloads']} -> current {measurement['current']['downloads']}). "
        "Conversion and causal uplift are unavailable without Marketplace analytics."
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
