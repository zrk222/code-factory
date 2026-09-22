from __future__ import annotations

import pytest

from factoryline.update_notifier import UpdateNotifierError, check_for_update


def _manifest():
    return {
        "schema": "factory.update-manifest.v1",
        "channel": "stable",
        "releases": [
            {"version": "0.46.8", "released_at": "2026-09-22T00:00:00Z", "summary": "Blueprint artifact-chain receipts."},
            {"version": "0.46.7", "released_at": "2026-09-19T00:00:00Z", "summary": "Previous release."},
        ],
    }


def test_update_notice_is_deterministic_and_authority_free() -> None:
    notice = check_for_update("0.46.7", _manifest())
    assert notice["marker"] == "UPDATE_AVAILABLE"
    assert notice["latest_version"] == "0.46.8"
    assert all(value is False for value in notice["authority"].values())
    assert check_for_update("0.46.8", _manifest())["marker"] == "UP_TO_DATE"


def test_update_manifest_rejects_wrong_channel_or_invalid_version() -> None:
    with pytest.raises(UpdateNotifierError, match="channel"):
        check_for_update("0.46.7", {**_manifest(), "channel": "nightly"})
    with pytest.raises(UpdateNotifierError, match="semantic version"):
        check_for_update("latest", _manifest())
