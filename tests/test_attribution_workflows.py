"""Behavior-focused tests for local workflow and projection entry points."""

from __future__ import annotations

import json
from pathlib import Path
import time

import pytest

from factoryline.continuation import discover_features
from factoryline.continuity import (
    ContinuityError,
    ContinuityPrincipal,
    recall_continuity_metadata_read_only,
)
from factoryline.failure_guidance import explain_failure
from factoryline.fix_workflow import FixWorkflowError, load_fix_json
from factoryline.integrations import SCMEvent, event_json, roles_from_groups
from factoryline.journey_proof import JourneyProofError, validate_failure_capsule
from factoryline.live_activity import LiveActivity, activity_snapshot, request_stop
from factoryline.live_feedback import LiveFeedbackError, load_live_json, validate_live_manifest
from factoryline.ops_telemetry import record_lifecycle
from factoryline.receipt_index import indexed_receipt_paths
from factoryline.refinement import pareto_win
from factoryline.run_metrics import export_public_metrics, load_run_receipts
from factoryline.savings import load_savings_pairs
from factoryline.update_notifier import read_manifest


def test_update_manifest_reader_normalizes_release_order(tmp_path: Path) -> None:
    path = tmp_path / "updates.json"
    path.write_text(
        json.dumps(
            {
                "schema": "factory.update-manifest.v1",
                "channel": "stable",
                "releases": [
                    {"version": "1.1.0", "released_at": "2026-01-02", "summary": "new"},
                    {"version": "1.0.0", "released_at": "2026-01-01", "summary": "old"},
                ],
            }
        ),
        encoding="utf-8",
    )

    result = read_manifest(path)

    assert [release["version"] for release in result["releases"]] == ["1.1.0", "1.0.0"]


def test_feature_discovery_uses_exact_spec_stems(tmp_path: Path) -> None:
    specs = tmp_path / "specs"
    specs.mkdir()
    (specs / "deep-review.md").write_text("# deep review", encoding="utf-8")
    (specs / "nested.notes.md").write_text("# not a feature id", encoding="utf-8")

    features = discover_features(tmp_path)

    assert features == ["deep-review"]


def test_read_only_continuity_rejects_missing_database_without_initializing_it(
    tmp_path: Path,
) -> None:
    database = tmp_path / "missing.sqlite3"
    principal = ContinuityPrincipal(
        subject="reader",
        tenant_id="tenant-a",
        roles=("reader",),
        purposes=("delivery-review@1",),
    )

    with pytest.raises(ContinuityError) as error:
        recall_continuity_metadata_read_only(
            database,
            principal,
            "tenant-a",
            purpose_ref="delivery-review@1",
            scope_ref="repo:sha256:abc123",
        )

    assert error.value.code == "E_CONTINUITY_UNAVAILABLE"
    assert database.exists() is False


def test_failure_guidance_keeps_causal_code_and_evidence() -> None:
    result = explain_failure("E_LANES", "unsupported lane", errors=["lane=unknown", ""])

    assert result["schema"] == "factory.failure_summary.v1"
    assert result["causal_code"] == "E_LANES"
    assert result["why"] == "unsupported lane"
    assert result["evidence"] == ["lane=unknown"]
    assert result["auto_correctable"] is False
    assert "Inspect the causal code and evidence" in result["next_action"]


def test_fix_manifest_loader_accepts_json_object(tmp_path: Path) -> None:
    path = tmp_path / "fix.json"
    path.write_text('{"schema":"factory.fix.v1","repairs":[]}', encoding="utf-8")

    assert load_fix_json(path) == {"schema": "factory.fix.v1", "repairs": []}


def test_fix_manifest_loader_rejects_json_array(tmp_path: Path) -> None:
    path = tmp_path / "fix.json"
    path.write_text('[{"schema":"factory.fix.v1","repairs":[]}]', encoding="utf-8")

    with pytest.raises(FixWorkflowError, match="JSON must be an object") as error:
        load_fix_json(path)

    assert error.value.code == "E_FIX_JSON"


def test_directory_groups_map_to_sorted_unique_known_roles() -> None:
    roles = roles_from_groups(
        ["release", "review", "release", "unknown"],
        {"release": "publisher", "review": "reviewer", "ignored": ""},
    )

    assert roles == ("publisher", "reviewer")


def test_scm_event_json_is_canonical_and_preserves_normalized_identity() -> None:
    event = SCMEvent(
        schema="factory.scm-event.v1",
        provider="github",
        tenant_id="tenant-a",
        delivery_id="delivery-1",
        event_type="pull_request",
        repository="acme/app",
        change_id="42",
        actor="alice",
        payload_sha256="a" * 64,
    )

    encoded = event_json(event)

    assert json.loads(encoded) == event.to_dict()
    assert encoded == json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")).encode()


def test_failure_capsule_validator_rejects_unbound_input(tmp_path: Path) -> None:
    with pytest.raises(JourneyProofError):
        validate_failure_capsule(tmp_path, {})


def test_live_manifest_validator_rejects_incomplete_contract(tmp_path: Path) -> None:
    with pytest.raises(LiveFeedbackError) as error:
        validate_live_manifest(tmp_path, {"schema": "wrong"})

    assert error.value.code == "E_LIVE_CONTRACT"


def test_live_json_loader_rejects_non_object_manifest(tmp_path: Path) -> None:
    path = tmp_path / "live.json"
    path.write_text("[]", encoding="utf-8")

    with pytest.raises(LiveFeedbackError) as error:
        load_live_json(path)

    assert error.value.code == "E_LIVE_JSON"


def test_lifecycle_writer_excludes_raw_arguments_and_workspace_paths(tmp_path: Path) -> None:
    destination = record_lifecycle(
        tmp_path,
        ["create", "private prompt text", "--root", str(tmp_path)],
        started_monotonic=time.monotonic(),
        exit_code=0,
        status="ok",
    )
    encoded = destination.read_text(encoding="utf-8")
    receipt = json.loads(encoded)

    assert receipt["schema"] == "factory.ops-lifecycle.v1"
    assert receipt["command_family"] == "create"
    assert receipt["exit_code"] == 0
    assert "private prompt text" not in encoded
    assert str(tmp_path) not in encoded


def test_receipt_path_index_discovers_only_json_receipts(tmp_path: Path) -> None:
    receipt_dir = tmp_path / "receipts"
    receipt_dir.mkdir()
    receipt = receipt_dir / "run.json"
    receipt.write_text('{"ok":true}', encoding="utf-8")
    (receipt_dir / "notes.txt").write_text("ignore", encoding="utf-8")

    paths = indexed_receipt_paths(tmp_path)

    assert paths == [receipt.resolve()]


def test_pareto_comparison_rejects_regressions_in_guarded_metrics() -> None:
    previous = {"qa": 0.8, "tests": 1.0}

    assert pareto_win({"qa": 0.9, "tests": 1.0}, previous, "qa") is True
    assert pareto_win({"qa": 0.9, "tests": 0.99}, previous, "qa") is False


def test_run_metrics_load_and_export_remain_aggregate_safe(tmp_path: Path) -> None:
    run_dir = tmp_path / ".factory" / "runs"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "schema": "factory.assembly-run.v1",
                "feature": "private-feature-name",
                "terminal": "completed",
                "elapsed_ms": 12,
                "command_count": 2,
                "retry_count": 0,
                "result_bytes": 64,
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "unrelated.json").write_text('{"schema":"foreign.v1"}', encoding="utf-8")

    runs = load_run_receipts(tmp_path)
    output = tmp_path / "public-metrics.json"
    written = export_public_metrics(tmp_path, output)
    report = json.loads(written.read_text(encoding="utf-8"))

    assert len(runs) == 1
    assert runs[0]["feature"] == "private-feature-name"
    assert report["schema"] == "factory.assembly-metrics.public.v1"
    assert report["runs"] == 1
    assert report["terminals"] == {"completed": 1}
    assert "private-feature-name" not in written.read_text(encoding="utf-8")


def test_savings_pair_loader_ignores_malformed_and_foreign_files(tmp_path: Path) -> None:
    pair_dir = tmp_path / ".factory" / "savings"
    pair_dir.mkdir(parents=True)
    (pair_dir / "broken.json").write_text("{", encoding="utf-8")
    (pair_dir / "foreign.json").write_text('{"schema":"foreign.v1"}', encoding="utf-8")

    assert load_savings_pairs(tmp_path) == []


def test_live_activity_stage_completion_updates_only_observed_counts(tmp_path: Path) -> None:
    activity = LiveActivity(tmp_path, "run-attribution", "feature", 2)
    activity.start()
    activity.stage_started("forgeline", "verify-tests")

    activity.stage_finished("forgeline", "verify-tests", "ok", wall_ms=23)
    state = activity_snapshot(tmp_path)

    assert state["completed_stages"] == 1
    assert state["failed_stages"] == 0
    assert state["recent_stages"][-1]["wall_ms"] == 23
    assert state["current_stage"] is None


def test_live_activity_reads_only_matching_run_cancellation(tmp_path: Path) -> None:
    activity = LiveActivity(tmp_path, "run-cancel", "feature", 1)
    activity.start()

    assert activity.cancel_requested() is False
    assert request_stop(tmp_path)["marker"] == "LIVE_ACTIVITY_STOP_REQUESTED"
    assert activity.cancel_requested() is True


def test_public_cdte_export_writes_aggregate_only_report(tmp_path: Path) -> None:
    from factoryline.cdte import export_public_cdte_report

    output = tmp_path / "reports" / "cdte.json"
    written = export_public_cdte_report(tmp_path, output)
    report = json.loads(written.read_text(encoding="utf-8"))

    assert report["marker"] == "CDTE_PUBLIC_REPORT"
    assert report["scans"] == 0
    assert "NO_CONSTRAINT_TEXT_EXPORTED" in report["markers"]
