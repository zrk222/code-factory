import json

import pytest

from factoryline.continuation import (
    ContinuationError,
    continue_assembly,
    resolve_feature,
    resolve_ssat,
)
from factoryline.run_metrics import public_metrics


def test_feature_inference_requires_exactly_one_candidate(tmp_path):
    with pytest.raises(ContinuationError) as error:
        resolve_feature(tmp_path, None)
    assert error.value.code == "FEATURE_SELECTION_REQUIRED"
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "only.md").write_text("# only", encoding="utf-8")
    assert resolve_feature(tmp_path, None) == ("only", True)
    (tmp_path / "specs" / "other.md").write_text("# other", encoding="utf-8")
    with pytest.raises(ContinuationError) as error:
        resolve_feature(tmp_path, None)
    assert error.value.candidates == ["only", "other"]


def test_ssat_resolution_prefers_specs_and_never_fuzzy_matches(tmp_path):
    (tmp_path / "specs").mkdir()
    expected = tmp_path / "specs" / "feature.ssat.yaml"
    expected.write_text("schema: x", encoding="utf-8")
    (tmp_path / "feature-old.ssat.yaml").write_text("schema: wrong", encoding="utf-8")
    assert resolve_ssat(tmp_path, "feature") == expected
    assert resolve_ssat(tmp_path, "missing") is None


def test_continue_writes_unknown_usage_receipt_and_safe_aggregate(tmp_path, monkeypatch):
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "feature.md").write_text("# feature", encoding="utf-8")
    monkeypatch.setattr(
        "factoryline.continuation.assemble",
        lambda root, feature, dry_run=False: {
            "feature": feature,
            "root": str(root),
            "run_id": "run-1",
            "stages": [{"module": "specline", "stage": "strict", "status": "ok"}],
            "paused_at": "architecture_approval",
            "rollup": {},
            "dry_run": dry_run,
        },
    )
    result = continue_assembly(tmp_path, "feature")
    assert result["status"] == "waiting_for_human"
    assert result["next_action"]["command"] == "forge gate architected feature"
    receipt = json.loads((tmp_path / ".factory" / "runs" / "run-1.json").read_text(encoding="utf-8"))
    assert receipt["usage"]["quality"] == "unknown"
    assert receipt["usage"]["tokens_in"] is None
    aggregate = public_metrics(tmp_path)
    assert aggregate["marker"] == "PUBLIC_METRICS_AGGREGATE_SAFE"
    assert aggregate["usage"]["quality"] == "unknown"
    assert aggregate["savings"]["tokens_saved"] is None
    encoded = json.dumps(aggregate)
    assert "feature" not in encoded
    assert str(tmp_path) not in encoded


def test_dry_run_does_not_write_receipt(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "factoryline.continuation.assemble",
        lambda root, feature, dry_run=False: {
            "feature": feature, "root": str(root), "run_id": "dry",
            "stages": [], "rollup": {}, "dry_run": dry_run,
        },
    )
    result = continue_assembly(tmp_path, "feature", dry_run=True)
    assert result["status"] == "completed"
    assert not (tmp_path / ".factory" / "runs").exists()
