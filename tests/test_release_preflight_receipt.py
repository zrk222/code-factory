from __future__ import annotations

import json

from scripts.verify_release_preflight import main, verify


def test_structured_ok_receipt_is_accepted(tmp_path):
    path = tmp_path / "release-preflight.json"
    path.write_text(json.dumps({"ok": True, "marker": "RELEASE_CANDIDATE_PREFLIGHT_WRITTEN"}), encoding="utf-8")
    assert verify(path)["ok"] is True
    assert main([str(path)]) == 0


def test_failed_or_malformed_receipt_is_rejected(tmp_path):
    failed = tmp_path / "failed.json"
    failed.write_text(json.dumps({"ok": False}), encoding="utf-8")
    malformed = tmp_path / "malformed.json"
    malformed.write_text("[]", encoding="utf-8")
    assert main([str(failed)]) == 1
    assert main([str(malformed)]) == 1
