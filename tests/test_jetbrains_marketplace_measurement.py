from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.jetbrains_marketplace_measurement import (
    BASELINE_SCHEMA,
    MEASUREMENT_SCHEMA,
    BaselineError,
    build_measurement,
    load_baseline,
)


def test_marketplace_measurement_reports_only_observed_download_movement() -> None:
    baseline = {
        "schema": BASELINE_SCHEMA,
        "recorded_at": "2026-08-04T05:00:00Z",
        "plugin_id": 33009,
        "downloads": 46,
        "listed_version": "0.7.1",
    }
    plugin = {
        "downloads": 53,
        "version": "0.8.3",
        "pricingModel": "FREE",
        "approve": False,
        "hasUnapprovedUpdate": True,
    }

    result = build_measurement(baseline, plugin)

    assert result["schema"] == MEASUREMENT_SCHEMA
    assert result["download_delta"] == 7
    assert result["download_delta_state"] == "observed"
    assert result["conversion_rate"] is None
    assert result["causal_uplift"] is None
    assert result["conversion_rate_state"] == "unavailable_without_marketplace_impressions_or_page_views"
    assert result["causal_uplift_state"] == "unavailable_without_a_controlled_experiment_or_attribution_data"


def test_marketplace_measurement_requires_a_well_formed_baseline(tmp_path: Path) -> None:
    invalid = tmp_path / "baseline.json"
    invalid.write_text(json.dumps({"schema": BASELINE_SCHEMA, "plugin_id": 33009, "downloads": -1}))

    with pytest.raises(BaselineError, match="BASELINE_DOWNLOADS_INVALID"):
        load_baseline(invalid)
