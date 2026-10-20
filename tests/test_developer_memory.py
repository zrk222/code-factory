from __future__ import annotations
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import pytest
from factoryline.change_review import ChangeReviewError
from factoryline.cli import main
from factoryline.continuity import ContinuityPrincipal, ContinuityStore
from factoryline.developer_memory import MAX_ACTIONS, developer_memory_brief
from factoryline.proof_reuse import record_proof
from factoryline.habituation import (
    HabituationError,
    MIN_AGENT_REVIEWS,
    MIN_DEFECT_SAMPLE,
    blind_spot_sample,
    calibrate_reviewer,
    defect_linkage,
    evaluate_gate,
    export_public_habituation_report,
    load_reviews,
    normalize_review,
    public_habituation_report,
    record_calibration,
    record_resample_outcome,
    record_review,
)
from factoryline.index_continuity import (
    INDEX_CONTINUITY_BASELINE_SCHEMA,
    INDEX_CONTINUITY_MARKER,
    IndexContinuityError,
    capture_continuity_baseline,
    compare_continuity,
    write_continuity_baseline,
)
import hashlib
from factoryline.learning_loop import (
    LearningLoopError,
    OBSERVER_GATE_PAYLOAD_TYPE,
    OBSERVER_GATES,
    build_fresh_worker_packet,
    diagnose_forensic_rejection,
    init_learning_task,
    plan_learning_experiment,
    promote_instruction_candidate,
    propose_instruction_candidate,
    restore_instruction_promotion,
    seal_forensic_rejection_packet,
    validate_forensic_rejection_packet,
    validate_instruction_candidate,
)
from factoryline.enterprise_receipts import generate_key_material, sign_payload


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _stale_proof_workspace(root: Path) -> None:
    (root / "input.txt").write_text("before", encoding="utf-8")
    (root / "output.txt").write_text("green", encoding="utf-8")
    record_proof(
        root,
        {
            "name": "unit",
            "command": ["python", "-m", "pytest"],
            "read_only": True,
            "inputs": ["input.txt"],
            "outputs": ["output.txt"],
        },
        elapsed_ms=50,
    )
    (root / "input.txt").write_text("after", encoding="utf-8")


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True, text=True
    )


def _continuity_record() -> dict[str, object]:
    return {
        "schema": "factory.continuity.record.v1",
        "tenant_id": "tenant-a",
        "record_type": "lesson",
        "memory_ref": "memory://private/strategy-42",
        "purpose": {"id": "delivery-review", "version": "1"},
        "scope": {"repository_ref": "repo:sha256:private"},
        "evidence_refs": ["receipt:sha256:proof-001"],
        "summary": "private continuity summary",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=3)).isoformat(),
    }


def _principal(subject: str, roles: tuple[str, ...]) -> ContinuityPrincipal:
    return ContinuityPrincipal(subject, "tenant-a", roles, ("delivery-review@1",))


def test_developer_memory_brief_makes_stale_proof_visual_action_without_writing(
    tmp_path: Path,
) -> None:
    _stale_proof_workspace(tmp_path)
    before = _files(tmp_path)

    brief = developer_memory_brief(tmp_path, changed=["input.txt"])

    assert brief["schema"] == "factory.developer-memory-brief.v1"
    assert "DEVELOPER_MEMORY_BRIEF_V1" in brief["markers"]
    assert "DEVELOPER_MEMORY_CHANGE_REVIEW_EXACT" in brief["markers"]
    assert "DEVELOPER_MEMORY_STALE_PROOF_ACTIONS" in brief["markers"]
    assert "DEVELOPER_MEMORY_VISUAL_EXPLAINED" in brief["markers"]
    assert brief["actions"][0]["kind"] == "rerun_stale_proof"
    assert brief["actions"][0]["evidence"]["proof_id"]
    assert (
        brief["actions"][0]["evidence"]["review_sha256"]
        == brief["change_review"]["review_sha256"]
    )
    assert brief["presentation"]["action_fields"] == [
        "what_changed",
        "why_it_matters",
        "do_this_next",
        "evidence",
    ]
    assert brief["authority"]["external_effects"] is False
    assert all(value is False for value in brief["authority"].values())
    assert _files(tmp_path) == before
    assert (
        developer_memory_brief(tmp_path, changed=["input.txt"])["brief_sha256"]
        == brief["brief_sha256"]
    )


def test_developer_memory_brief_withholds_continuity_bodies(tmp_path: Path) -> None:
    store = ContinuityStore(tmp_path / ".factory" / "continuity.sqlite3")
    store.record(
        _principal("worker", ("writer",)),
        _continuity_record(),
        idempotency_key="memory",
        record_id="private-record",
    )
    store.promote(
        _principal("reviewer", ("promoter",)),
        "tenant-a",
        "private-record",
        reason="independent review",
    )

    brief = developer_memory_brief(tmp_path, changed=["app/service.py"])
    rendered = json.dumps(brief, sort_keys=True)

    assert "DEVELOPER_MEMORY_REDACTED_CONTINUITY" in brief["markers"]
    assert brief["continuity"]["record_ids"] == ["private-record"]
    assert "memory://private/strategy-42" not in rendered
    assert "private continuity summary" not in rendered
    assert brief["actions"][0]["kind"] == "bind_changed_path_to_proof"


def test_developer_memory_attributes_observed_local_git_contributors_without_claiming_seats(
    tmp_path: Path,
) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.name", "Ada Lovelace")
    _git(tmp_path, "config", "user.email", "ada@example.test")
    (tmp_path / "app.py").write_text("first\n", encoding="utf-8")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-m", "Ada adds app")
    _git(tmp_path, "config", "user.name", "Grace Hopper")
    _git(tmp_path, "config", "user.email", "grace@example.test")
    (tmp_path / "app.py").write_text("second\n", encoding="utf-8")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-m", "Grace updates app")

    brief = developer_memory_brief(tmp_path, changed=["app.py"])

    assert "DEVELOPER_MEMORY_TEAM_ATTRIBUTION_LOCAL_GIT" in brief["markers"]
    assert brief["team"]["source"] == {
        "kind": "local_git_history",
        "directory_connected": False,
        "roster_completeness": "observed_contributors_only",
        "scope": "all local Git refs",
    }
    names = {seat["display_name"] for seat in brief["team"]["seats"]}
    assert names == {"Ada Lovelace", "Grace Hopper"}
    assert all("email" not in seat for seat in brief["team"]["seats"])
    assert brief["actions"][0]["contributor_seat_ids"]
    assert "billing" not in json.dumps(brief["team"]["source"]).lower()
    assert (
        "not a verified identity-provider or billing-seat roster"
        in brief["team"]["scope_limits"][0]
    )


def test_developer_memory_reports_unavailable_change_set_without_inference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(*_args, **_kwargs):
        raise ChangeReviewError("DIFF_BASE_UNAVAILABLE", "base unavailable")

    monkeypatch.setattr("factoryline.developer_memory.review_change", unavailable)

    brief = developer_memory_brief(tmp_path)

    assert "DEVELOPER_MEMORY_UNAVAILABLE_EXPLICIT" in brief["markers"]
    assert brief["actions"] == [brief["actions"][0]]
    assert brief["actions"][0]["kind"] == "change_review_unavailable"
    assert brief["actions"][0]["evidence"]["failure_code"] == "DIFF_BASE_UNAVAILABLE"
    assert brief["change_review"]["changed_paths"] == []
    assert "productivity" in brief["scope_limits"][0]


def test_developer_memory_caps_action_cards_before_lower_priority_advice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = [f"src/path-{index}.py" for index in range(MAX_ACTIONS + 4)]
    review = {
        "base": "main",
        "input_source": "explicit",
        "changed_paths": paths,
        "review_sha256": "a" * 64,
        "impact": {"unmatched_changed_paths": paths, "rerun_proofs": []},
        "coverage": {"ok": True, "uncovered": []},
        "risk": {"rerun_stages": []},
        "unproven_claims": [],
    }
    monkeypatch.setattr(
        "factoryline.developer_memory.review_change", lambda *_args, **_kwargs: review
    )

    brief = developer_memory_brief(tmp_path, changed=paths)

    assert len(brief["actions"]) == MAX_ACTIONS
    assert all(
        action["kind"] == "bind_changed_path_to_proof" for action in brief["actions"]
    )
    assert brief["next_action"]["id"] == "scope-gap:src/path-0.py"


def test_developer_memory_cli_is_machine_readable_and_read_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _stale_proof_workspace(tmp_path)
    before = _files(tmp_path)

    assert (
        main(
            [
                "memory",
                "brief",
                "--root",
                str(tmp_path),
                "--changed",
                "input.txt",
                "--json",
            ]
        )
        == 0
    )

    brief = json.loads(capsys.readouterr().out)
    assert brief["schema"] == "factory.developer-memory-brief.v1"
    assert brief["next_action"]["action"] == "rerun_stale_proof"
    assert _files(tmp_path) == before


"""Habituation gate — calibrating the human approval signal.

Grouped by the guarantee under test. The guarantees that matter are: drift is
measured against a reviewer's own baseline and never against peers, an
uncorrected proxy cannot block a merge, and no identity or per-person row
reaches a public export.
"""


def review(
    rid,
    reviewer="alice",
    kind="agent",
    seconds=60.0,
    lines=100,
    comments=3,
    approved=True,
):
    return {
        "review_id": rid,
        "reviewer": reviewer,
        "author_kind": kind,
        "review_seconds": seconds,
        "changed_lines": lines,
        "inline_comments": comments,
        "approved": approved,
    }


def seed(root, *, agent_seconds=10.0, human_seconds=60.0, n=6, reviewer="alice"):
    """Habituated reviewer: fast on agent code, slow on human code.

    Review ids are namespaced per reviewer because a review id identifies a
    reviewer-and-change pair, not a change alone.
    """
    who = reviewer.split("@")[0]
    for i in range(n):
        record_review(root, review(f"a-{who}-{i}", reviewer, "agent", agent_seconds))
        record_review(root, review(f"h-{who}-{i}", reviewer, "human", human_seconds))


# ---------------------------------------------------------------------------
# Event validation
# ---------------------------------------------------------------------------
def test_scrutiny_ratio_is_seconds_per_hundred_lines():
    r = normalize_review(review("r-1", seconds=60.0, lines=200))
    assert r["scrutiny_ratio"] == 30.0


def test_zero_changed_lines_refused():
    """A review of nothing has no scrutiny ratio; inventing one poisons the window."""
    with pytest.raises(HabituationError) as exc:
        normalize_review(review("r-1", lines=0))
    assert exc.value.code == "CHANGED_LINES_INVALID"


def test_boolean_changed_lines_refused():
    with pytest.raises(HabituationError) as exc:
        normalize_review({**review("r-1"), "changed_lines": True})
    assert exc.value.code == "CHANGED_LINES_INVALID"


def test_unknown_author_kind_refused():
    with pytest.raises(HabituationError) as exc:
        normalize_review({**review("r-1"), "author_kind": "robot"})
    assert exc.value.code == "AUTHOR_KIND_INVALID"


def test_reviewer_identity_is_hashed_not_stored():
    r = normalize_review(review("r-1", reviewer="alice@example.com"))
    assert "alice" not in json.dumps(r)
    assert len(r["reviewer_key"]) == 16


def test_identity_hash_is_case_and_space_stable():
    a = normalize_review(review("r-1", reviewer="Alice@Example.com "))
    b = normalize_review(review("r-2", reviewer="alice@example.com"))
    assert a["reviewer_key"] == b["reviewer_key"]


def test_review_overwrite_refused(tmp_path):
    record_review(tmp_path, review("r-1"))
    with pytest.raises(HabituationError) as exc:
        record_review(tmp_path, review("r-1"))
    assert exc.value.code == "REVIEW_OVERWRITE_REFUSED"
    record_review(tmp_path, review("r-1"), replace=True)


# ---------------------------------------------------------------------------
# Calibration: self-baseline only
# ---------------------------------------------------------------------------
def test_drift_detected_against_own_baseline(tmp_path):
    seed(tmp_path, agent_seconds=10.0, human_seconds=60.0)
    result = calibrate_reviewer(load_reviews(tmp_path))
    assert result["withheld"] is False
    assert result["scrutiny_drift"] == pytest.approx(1 - 10 / 60)
    assert result["drift_band"] == "block"


def test_no_drift_when_scrutiny_matches(tmp_path):
    seed(tmp_path, agent_seconds=60.0, human_seconds=60.0)
    result = calibrate_reviewer(load_reviews(tmp_path))
    assert result["scrutiny_drift"] == 0.0
    assert result["drift_band"] == "nominal"


def test_drift_withheld_below_agent_sample_floor(tmp_path):
    for i in range(MIN_AGENT_REVIEWS - 1):
        record_review(tmp_path, review(f"a-{i}", kind="agent"))
    for i in range(10):
        record_review(tmp_path, review(f"h-{i}", kind="human"))
    result = calibrate_reviewer(load_reviews(tmp_path))
    assert result["withheld"] is True
    assert result["scrutiny_drift"] is None
    assert "agent-authored reviews observed" in result["withheld_reason"]


def test_drift_withheld_without_a_personal_baseline(tmp_path):
    """No human-authored baseline means no comparison. Comparing against other
    reviewers would attribute an exposure effect to a person."""
    for i in range(10):
        record_review(tmp_path, review(f"a-{i}", kind="agent"))
    result = calibrate_reviewer(load_reviews(tmp_path))
    assert result["withheld"] is True
    assert "own baseline" in result["withheld_reason"]


def test_calibration_receipt_marks_self_baseline(tmp_path):
    seed(tmp_path)
    receipt = record_calibration(tmp_path)
    assert "BASELINE_IS_SELF_NOT_PEER" in receipt["markers"]
    assert "SCRUTINY_FLOOR_BREACHED" in receipt["markers"]


def test_calibration_refuses_empty_corpus(tmp_path):
    with pytest.raises(HabituationError) as exc:
        record_calibration(tmp_path)
    assert exc.value.code == "NO_REVIEWS"


def test_separate_reviewers_calibrated_independently(tmp_path):
    seed(tmp_path, reviewer="alice", agent_seconds=10.0, human_seconds=60.0)
    seed(tmp_path, reviewer="bob", agent_seconds=60.0, human_seconds=60.0)
    receipt = record_calibration(tmp_path)
    assert receipt["reviewers"] == 2
    bands = sorted(c["drift_band"] for c in receipt["calibrations"])
    assert bands == ["block", "nominal"]


# ---------------------------------------------------------------------------
# Blind-spot sampling
# ---------------------------------------------------------------------------
def test_sampling_is_deterministic(tmp_path):
    seed(tmp_path, n=20)
    first = blind_spot_sample(tmp_path, rate=50)
    second = blind_spot_sample(tmp_path, rate=50)
    assert first["selected"] == second["selected"]


def test_sampling_only_draws_from_low_scrutiny_half(tmp_path):
    for i in range(10):
        record_review(tmp_path, review(f"fast-{i}", kind="agent", seconds=1.0))
        record_review(tmp_path, review(f"slow-{i}", kind="agent", seconds=999.0))
    sample = blind_spot_sample(tmp_path, rate=100)
    assert all(s.startswith("fast-") for s in sample["selected"])


def test_invalid_sample_rate_refused(tmp_path):
    seed(tmp_path)
    for bad in (0, 101, True):
        with pytest.raises(HabituationError) as exc:
            blind_spot_sample(tmp_path, rate=bad)
        assert exc.value.code == "SAMPLE_RATE_INVALID"


def test_resample_reviewer_must_differ_from_approver(tmp_path):
    """A signal cannot correct itself; reuses the learning-loop identity rule."""
    record_review(tmp_path, review("a-1", reviewer="alice"))
    with pytest.raises(HabituationError) as exc:
        record_resample_outcome(tmp_path, "a-1", defect_found=True, reviewer="alice")
    assert exc.value.code == "RESAMPLE_IDENTITY_CONFLICT"


def test_resample_outcome_recorded(tmp_path):
    record_review(tmp_path, review("a-1", reviewer="alice"))
    receipt = record_resample_outcome(
        tmp_path, "a-1", defect_found=True, reviewer="bob"
    )
    assert receipt["defect_found"] is True
    assert "alice" not in json.dumps(receipt) and "bob" not in json.dumps(receipt)


# ---------------------------------------------------------------------------
# The central safety property: an uncorrected proxy cannot block
# ---------------------------------------------------------------------------
def test_breach_alone_does_not_block(tmp_path):
    seed(tmp_path, agent_seconds=5.0, human_seconds=60.0)
    gate = evaluate_gate(tmp_path, allow_block=False)
    assert gate["action"] == "second_approver"
    assert gate["blocking"] is False


def test_blocking_refused_while_proxy_is_uncorrected(tmp_path):
    """allow_block is requested but no resample outcomes exist."""
    seed(tmp_path, agent_seconds=5.0, human_seconds=60.0)
    gate = evaluate_gate(tmp_path, allow_block=True)
    assert gate["blocking"] is False
    assert gate["action"] == "second_approver"
    assert "uncorrected proxy" in gate["reason"]
    assert "PROXY_UNCORRECTED" in gate["markers"]


def test_blocking_permitted_once_resampling_exists(tmp_path):
    seed(tmp_path, agent_seconds=5.0, human_seconds=60.0)
    record_resample_outcome(tmp_path, "a-alice-0", defect_found=False, reviewer="bob")
    gate = evaluate_gate(tmp_path, allow_block=True)
    assert gate["blocking"] is True
    assert gate["action"] == "fail_closed"
    assert "FAIL_CLOSED_ENGAGED" in gate["markers"]


def test_nominal_scrutiny_takes_no_action(tmp_path):
    seed(tmp_path, agent_seconds=60.0, human_seconds=60.0)
    gate = evaluate_gate(tmp_path, allow_block=True)
    assert gate["action"] == "none"
    assert gate["blocking"] is False


def test_warn_band_only_surfaces(tmp_path):
    seed(tmp_path, agent_seconds=25.0, human_seconds=60.0)  # ~58% drift, below block
    gate = evaluate_gate(tmp_path, allow_block=True)
    assert gate["action"] == "surface"
    assert gate["blocking"] is False


# ---------------------------------------------------------------------------
# Defect linkage: modeled, withheld by default, never individual blame
# ---------------------------------------------------------------------------
def test_defect_linkage_withheld_by_default(tmp_path):
    seed(tmp_path)
    linkage = defect_linkage(tmp_path)
    assert linkage["withheld"] is True
    assert linkage["tier"] == "modeled"
    assert linkage["assumptions"]


def test_defect_linkage_withheld_below_sample_floor(tmp_path):
    seed(tmp_path)
    record_resample_outcome(tmp_path, "a-alice-0", defect_found=True, reviewer="bob")
    linkage = defect_linkage(tmp_path, enable=True)
    assert linkage["withheld"] is True
    assert str(MIN_DEFECT_SAMPLE) in linkage["withheld_reason"]


def test_defect_linkage_emits_with_limits_once_sampled(tmp_path):
    for i in range(MIN_DEFECT_SAMPLE):
        record_review(tmp_path, review(f"a-{i}", reviewer="alice"))
        record_resample_outcome(
            tmp_path, f"a-{i}", defect_found=(i % 4 == 0), reviewer="bob"
        )
    linkage = defect_linkage(tmp_path, enable=True)
    assert linkage["withheld"] is False
    assert linkage["defect_rate_in_low_scrutiny_sample"] == 0.25
    assert "not attributable to any individual" in linkage["interpretation_limit"]
    assert any(
        "not evidence that low scrutiny caused" in a for a in linkage["assumptions"]
    )


# ---------------------------------------------------------------------------
# Disclosure boundary
# ---------------------------------------------------------------------------
def test_public_report_exports_no_identity_or_per_person_row(tmp_path):
    seed(tmp_path, reviewer="alice@example.com")
    seed(tmp_path, reviewer="bob@example.com", n=6)
    report = public_habituation_report(tmp_path)
    blob = json.dumps(report)
    assert "alice" not in blob and "bob" not in blob
    for row in load_reviews(tmp_path):
        assert row["reviewer_key"] not in blob, (
            "pseudonymous key still identifies a person"
        )
        assert row["review_id"] not in blob
    assert "calibrations" not in report, "no per-reviewer rows may be exported"


def test_public_report_carries_band_distribution_only(tmp_path):
    seed(tmp_path, reviewer="alice", agent_seconds=5.0, human_seconds=60.0)
    seed(tmp_path, reviewer="bob", agent_seconds=60.0, human_seconds=60.0)
    report = public_habituation_report(tmp_path)
    assert report["reviewers_by_drift_band"] == {"block": 1, "nominal": 1}
    assert report["reviewers_observed"] == 2


def test_public_report_on_empty_store(tmp_path):
    report = public_habituation_report(tmp_path)
    assert report["reviews_observed"] == 0
    assert report["median_scrutiny_drift"] is None
    assert report["defect_linkage"]["withheld"] is True


def test_public_report_export_round_trips(tmp_path):
    seed(tmp_path)
    out = export_public_habituation_report(tmp_path, tmp_path / "pub.json")
    assert (
        json.loads(out.read_text(encoding="utf-8"))["marker"]
        == "HABITUATION_PUBLIC_REPORT"
    )


def _baseline(root: Path) -> Path:
    output = root / ".factory" / "index-continuity" / "baseline.json"
    write_continuity_baseline(capture_continuity_baseline(root), root, output)
    return output


def test_baseline_is_explicit_local_and_never_stores_source_contents(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"name":"demo-secret"}', encoding="utf-8")
    baseline = capture_continuity_baseline(tmp_path)
    output = tmp_path / ".factory" / "index-continuity" / "baseline.json"

    assert baseline["schema"] == INDEX_CONTINUITY_BASELINE_SCHEMA
    assert baseline["marker"] == INDEX_CONTINUITY_MARKER
    assert all(value is False for value in baseline["authority"].values())
    assert "demo-secret" not in json.dumps(baseline)
    assert (
        write_continuity_baseline(baseline, tmp_path, output)
        == ".factory/index-continuity/baseline.json"
    )
    with pytest.raises(IndexContinuityError, match="workspace root"):
        write_continuity_baseline(baseline, tmp_path, tmp_path.parent / "outside.json")


def test_identical_baseline_is_stable_and_does_not_fabricate_a_duration(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"name":"demo"}', encoding="utf-8")
    result = compare_continuity(tmp_path, _baseline(tmp_path))

    assert result["review_scope"] == "stable"
    assert result["changes"] == []
    assert "no reindexing duration" in json.dumps(result).lower()
    assert "INDEX_CONTINUITY_NO_IDE_MUTATION" in result["markers"]


def test_changed_manifest_requires_broad_reanalysis_with_exact_path(tmp_path: Path):
    manifest = tmp_path / "package.json"
    manifest.write_text('{"name":"demo","version":"1"}', encoding="utf-8")
    baseline = _baseline(tmp_path)
    manifest.write_text('{"name":"demo","version":"2"}', encoding="utf-8")

    result = compare_continuity(tmp_path, baseline)

    assert result["review_scope"] == "broad_reanalysis"
    file_change = next(
        item for item in result["changes"] if item["kind"] == "structural_files"
    )
    assert file_change["files"] == [{"path": "package.json", "change": "changed"}]


def test_managed_directory_drift_is_targeted_not_a_corruption_claim(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    baseline = _baseline(tmp_path)
    generated = tmp_path / "build"
    generated.mkdir()
    (generated / "bundle.js").write_text("output", encoding="utf-8")

    result = compare_continuity(tmp_path, baseline)

    assert result["review_scope"] == "targeted_reanalysis"
    assert "corrupt" not in json.dumps(result).lower()


def test_tampered_or_invalid_baseline_fails_closed(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='demo'\n", encoding="utf-8"
    )
    baseline = _baseline(tmp_path)
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    payload["source_roots"] = ["unexpected"]
    baseline.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(IndexContinuityError, match="digest"):
        compare_continuity(tmp_path, baseline)


def test_cli_end_to_end_baseline_then_compare(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text("[package]\nname='demo'\n", encoding="utf-8")
    baseline = tmp_path / ".factory" / "index-continuity" / "baseline.json"

    assert (
        main(
            [
                "workspace",
                "continuity",
                "baseline",
                "--root",
                str(tmp_path),
                "--out",
                str(baseline),
                "--json",
            ]
        )
        == 0
    )
    captured = json.loads(capsys.readouterr().out)
    assert captured["baseline_path"] == ".factory/index-continuity/baseline.json"
    manifest.write_text("[package]\nname='changed'\n", encoding="utf-8")
    assert (
        main(
            [
                "workspace",
                "continuity",
                "compare",
                "--root",
                str(tmp_path),
                "--baseline",
                str(baseline),
                "--json",
            ]
        )
        == 0
    )
    compared = json.loads(capsys.readouterr().out)
    assert compared["review_scope"] == "broad_reanalysis"


MILESTONES = [
    {
        "id": "spec",
        "criteria": [
            {"id": "requirements", "statement": "Requirements are executable."}
        ],
    },
    {
        "id": "runtime",
        "criteria": [{"id": "smoke", "statement": "Runtime smoke passes."}],
    },
]

OBSERVER_MILESTONES = [
    {
        "id": "skill-repair",
        "criteria": [
            {"id": key, "statement": f"Run and bind {key}."}
            for key in (
                "forensic-replay",
                "holdout-regression",
                "false-positive-control",
                "specialty-ai-review",
            )
        ],
    }
]


def _observer_candidate(tmp_path: Path):
    evidence = tmp_path / "rejection.json"
    evidence.write_text('{"mutation":"survived"}\n', encoding="utf-8")
    candidate_sha = "a" * 64
    source_sha = "b" * 64
    packet = seal_forensic_rejection_packet(
        tmp_path,
        {
            "schema": "factory.forensic-rejection.v1",
            "candidate_sha256": candidate_sha,
            "source_sha256": source_sha,
            "failure_class": "mutation_survivor",
            "failure_id": "mutant-survived-01",
            "failed_mutation_seeds": [
                {
                    "id": "mutant-01",
                    "seed_sha256": "c" * 64,
                    "expected": "test failure",
                    "observed": "test pass",
                    "evidence_id": "mutation-run",
                }
            ],
            "policy_breaches": [],
            "counterfactual_profiles": [],
            "review_corrections": [],
            "validator_versions": [{"name": "factory", "version": "0.47.0"}],
            "evidence_bindings": [
                {
                    "id": "mutation-run",
                    "kind": "mutation-test",
                    "path": str(evidence),
                    "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                }
            ],
            "unknowns": [],
        },
    )
    packet_path = tmp_path / "forensic.json"
    packet_path.write_text(json.dumps(packet), encoding="utf-8")
    task = init_learning_task(
        tmp_path, "observer", "owner", "Harden worker test skills", OBSERVER_MILESTONES
    )
    outcome = tmp_path / "outcome.json"
    outcome.write_text(
        json.dumps({"candidate_sha256": candidate_sha, "source_sha256": source_sha}),
        encoding="utf-8",
    )
    candidate = propose_instruction_candidate(
        Path(task["path"]),
        tmp_path,
        "skill-repair",
        "observer-agent",
        outcome,
        [
            {
                "dimension": "d6_output_processing",
                "instruction": "Assert the mutated state is rejected.",
            }
        ],
        forensic_packet_path=packet_path,
    )
    return task, candidate, packet_path, packet


def _observer_gate_evidence(
    tmp_path: Path,
    packet: dict,
    *,
    signed: bool = True,
    runner_role: str = "observer-gate-runner",
):
    trust_dir = tmp_path.parent / f"{tmp_path.name}-observer-trust"
    runner = generate_key_material(
        out_dir=trust_dir / "runner",
        keyid="audit-runner",
        identity="factory-audit:runner",
        issuer="https://audit.example",
    )
    reviewer = generate_key_material(
        out_dir=trust_dir / "reviewer",
        keyid="specialty-reviewer",
        identity="specialty-ai:cf-reviewer",
        issuer="https://review.example",
    )
    trust_root = trust_dir / "trust-root.json"
    trust_root.write_text(
        json.dumps(
            {
                "schema": "factory.trust.root.v1",
                "version": 1,
                "keys": [
                    {
                        "keyid": key["keyid"],
                        "algorithm": "ed25519",
                        "public_key": Path(key["public_key"])
                        .read_text(encoding="ascii")
                        .strip(),
                        "identity": key["identity"],
                        "issuer": key["issuer"],
                        "roles": [
                            runner_role if key is runner else "specialty-ai-reviewer"
                        ],
                    }
                    for key in (runner, reviewer)
                ],
            }
        ),
        encoding="utf-8",
    )
    results = []
    for gate in sorted(OBSERVER_GATES):
        is_review = gate == "specialty-ai-review"
        payload = {
            "schema": (
                "factory.specialty-ai-review.v1"
                if is_review
                else "factory.observer-replay.v1"
            ),
            "candidate_sha256": packet["candidate_sha256"],
            "forensic_packet_sha256": packet["packet_sha256"],
        }
        if is_review:
            payload.update(
                {
                    "reviewer_agent": "specialty-ai:cf-reviewer",
                    "verdict": "APPROVE",
                    "findings": [],
                }
            )
        else:
            payload.update({"check_id": gate, "result": "PASS"})
        key = reviewer if is_review else runner
        evidence = payload
        if signed:
            evidence = sign_payload(
                payload,
                payload_type=OBSERVER_GATE_PAYLOAD_TYPE,
                private_key_path=Path(key["private_key"]),
                keyid=key["keyid"],
                identity=key["identity"],
                issuer=key["issuer"],
            )
        path = tmp_path / f"{gate}.json"
        path.write_text(json.dumps(evidence), encoding="utf-8")
        results.append({"id": gate, "passed": True, "evidence": [str(path)]})
    return results, trust_root


def _candidate(tmp_path: Path):
    task = init_learning_task(
        tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES
    )
    outcome = tmp_path / "outcome.json"
    outcome.write_text('{"requirements": "passed"}\n', encoding="utf-8")
    candidate = propose_instruction_candidate(
        Path(task["path"]),
        tmp_path,
        "spec",
        "worker-1",
        outcome,
        [
            {
                "dimension": "d6_output_processing",
                "instruction": "Run the strict requirement mutation gate before implementation.",
            }
        ],
    )
    evidence = tmp_path / "strict.json"
    evidence.write_text('{"valid": true}\n', encoding="utf-8")
    return task, candidate, evidence


def test_fresh_packet_excludes_prior_reasoning_and_worker_outputs(tmp_path: Path):
    task = init_learning_task(
        tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES
    )
    packet = build_fresh_worker_packet(Path(task["path"]), "spec", "worker-2")
    assert packet["context"] == {
        "fresh": True,
        "prior_reasoning": [],
        "prior_worker_outputs": [],
    }
    assert packet["instructions"] == []
    assert packet["authority"]["promote_instructions"] is False


def test_candidate_cannot_self_validate(tmp_path: Path):
    _task, candidate, evidence = _candidate(tmp_path)
    results = [{"id": "requirements", "passed": True, "evidence": [str(evidence)]}]
    with pytest.raises(LearningLoopError, match="VALIDATOR_IDENTITY_DISTINCT"):
        validate_instruction_candidate(
            Path(candidate["path"]), tmp_path, "worker-1", results
        )


def test_validation_requires_exact_complete_criteria(tmp_path: Path):
    _task, candidate, _evidence = _candidate(tmp_path)
    with pytest.raises(LearningLoopError, match="MILESTONE_VALIDATION_INCOMPLETE"):
        validate_instruction_candidate(
            Path(candidate["path"]), tmp_path, "validator", []
        )


def test_human_promotes_validated_candidate_to_aku_and_next_milestone(tmp_path: Path):
    task, candidate, evidence = _candidate(tmp_path)
    results = [{"id": "requirements", "passed": True, "evidence": [str(evidence)]}]
    validation = validate_instruction_candidate(
        Path(candidate["path"]), tmp_path, "validator", results
    )
    promotion = promote_instruction_candidate(Path(validation["path"]), "owner")
    assert promotion["aku"]["procedure"] == candidate["instructions"]
    assert promotion["aku"]["metadata"]["control_dimensions"] == [
        "d6_output_processing"
    ]
    assert promotion["aku"]["governance"]["autonomy"] == "supervised"
    assert "HUMAN_PROMOTION_BOUND" in promotion["markers"]

    refined_packet = build_fresh_worker_packet(Path(task["path"]), "spec", "worker-2")
    assert refined_packet["instructions"] == candidate["instructions"]
    assert (
        refined_packet["harness_adaptation"]["d6_output_processing"]
        == candidate["instructions"]
    )
    assert refined_packet["context"]["prior_worker_outputs"] == []

    packet = build_fresh_worker_packet(Path(task["path"]), "runtime", "worker-2")
    assert packet["milestone"]["id"] == "runtime"
    assert packet["context"]["prior_reasoning"] == []


def test_promotion_history_is_immutable_and_owner_can_restore_prior_version(
    tmp_path: Path, capsys
):
    task, candidate, evidence = _candidate(tmp_path)
    validation = validate_instruction_candidate(
        Path(candidate["path"]),
        tmp_path,
        "validator-1",
        [{"id": "requirements", "passed": True, "evidence": [str(evidence)]}],
    )
    first = promote_instruction_candidate(Path(validation["path"]), "owner")

    outcome2 = tmp_path / "outcome-v2.json"
    outcome2.write_text('{"requirements": "revised"}\n', encoding="utf-8")
    candidate2 = propose_instruction_candidate(
        Path(task["path"]),
        tmp_path,
        "spec",
        "worker-2",
        outcome2,
        [
            {
                "dimension": "d6_output_processing",
                "instruction": "Assert both accepted and rejected boundary cases.",
            }
        ],
    )
    evidence2 = tmp_path / "strict-v2.json"
    evidence2.write_text('{"valid": true, "boundaries": true}\n', encoding="utf-8")
    validation2 = validate_instruction_candidate(
        Path(candidate2["path"]),
        tmp_path,
        "validator-2",
        [{"id": "requirements", "passed": True, "evidence": [str(evidence2)]}],
    )
    second = promote_instruction_candidate(
        Path(validation2["path"]), "owner", force=True
    )
    history = (
        Path(second["path"]).parent
        / "history"
        / (f"spec-{first['promotion_sha256'][:16]}.json")
    )
    assert (
        json.loads(history.read_text(encoding="utf-8"))["promotion_sha256"]
        == first["promotion_sha256"]
    )

    with pytest.raises(LearningLoopError, match="OWNER_MISMATCH"):
        restore_instruction_promotion(
            Path(task["path"]), "different-owner", first["promotion_sha256"]
        )
    assert (
        main(
            [
                "learning",
                "promote",
                "--restore",
                first["promotion_sha256"],
                "--task",
                task["path"],
                "--owner",
                "owner",
                "--json",
            ]
        )
        == 0
    )
    restored = json.loads(capsys.readouterr().out)
    assert restored["restored"] is True
    assert restored["promotion_sha256"] == first["promotion_sha256"]
    active = json.loads(Path(restored["path"]).read_text(encoding="utf-8"))
    assert active["promotion_sha256"] == first["promotion_sha256"]
    assert restored["rollback"]["from_promotion_sha256"] == second["promotion_sha256"]
    assert restored["rollback"]["to_promotion_sha256"] == first["promotion_sha256"]
    assert (
        build_fresh_worker_packet(Path(task["path"]), "spec", "worker-after-rollback")[
            "instruction_version"
        ]
        == 1
    )


def test_rollback_rejects_unknown_promotion_hash(tmp_path: Path):
    task = init_learning_task(
        tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES
    )
    with pytest.raises(LearningLoopError, match="PROMOTION_HISTORY_NOT_FOUND"):
        restore_instruction_promotion(Path(task["path"]), "owner", "a" * 64)


def test_candidate_rejects_unclassified_harness_edit(tmp_path: Path):
    task = init_learning_task(
        tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES
    )
    outcome = tmp_path / "outcome.json"
    outcome.write_text("{}\n", encoding="utf-8")
    with pytest.raises(LearningLoopError, match="INSTRUCTION_CANDIDATE_INVALID"):
        propose_instruction_candidate(
            Path(task["path"]),
            tmp_path,
            "spec",
            "worker",
            outcome,
            [{"dimension": "prompt_magic", "instruction": "Try harder."}],
        )


def test_forensic_observer_binds_packet_replay_specialty_review_and_deferred_skill(
    tmp_path: Path,
):
    task, candidate, packet_path, packet = _observer_candidate(tmp_path)
    verified = validate_forensic_rejection_packet(tmp_path, packet_path)
    diagnosis = diagnose_forensic_rejection(verified)
    assert diagnosis["cause"] == "weak_oracle_or_assertion"
    assert diagnosis["confidence"] == "hypothesis_requires_replay"
    assert candidate["forensic_rejection"]["packet_sha256"] == packet["packet_sha256"]

    results, trust_root = _observer_gate_evidence(tmp_path, packet)

    validation = validate_instruction_candidate(
        Path(candidate["path"]),
        tmp_path,
        "specialty-ai:cf-reviewer",
        results,
        observer_trust_root=trust_root,
    )
    promotion = promote_instruction_candidate(Path(validation["path"]), "owner")
    packet = build_fresh_worker_packet(
        Path(task["path"]), "skill-repair", "worker-next"
    )
    assert (
        promotion["aku"]["metadata"]["provenance"]["forensic_packet_sha256"]
        == verified["packet_sha256"]
    )
    assert packet["instruction_version"] == 1
    assert packet["instructions"] == candidate["instructions"]


def test_forensic_observer_rejects_unsigned_gate_receipts(tmp_path: Path):
    _, candidate, _, packet = _observer_candidate(tmp_path)
    results, trust_root = _observer_gate_evidence(tmp_path, packet, signed=False)
    with pytest.raises(LearningLoopError, match="OBSERVER_SIGNATURE_INVALID"):
        validate_instruction_candidate(
            Path(candidate["path"]),
            tmp_path,
            "specialty-ai:cf-reviewer",
            results,
            observer_trust_root=trust_root,
        )


def test_forensic_observer_rejects_trusted_key_without_gate_role(tmp_path: Path):
    _, candidate, _, packet = _observer_candidate(tmp_path)
    results, trust_root = _observer_gate_evidence(
        tmp_path, packet, runner_role="worker"
    )
    with pytest.raises(LearningLoopError, match="OBSERVER_SIGNATURE_INVALID"):
        validate_instruction_candidate(
            Path(candidate["path"]),
            tmp_path,
            "specialty-ai:cf-reviewer",
            results,
            observer_trust_root=trust_root,
        )


def test_forensic_observer_requires_trust_root_outside_candidate_workspace(
    tmp_path: Path,
):
    _, candidate, _, packet = _observer_candidate(tmp_path)
    results, _ = _observer_gate_evidence(tmp_path, packet)
    in_workspace = tmp_path / "untrusted-root.json"
    in_workspace.write_text("{}", encoding="utf-8")
    with pytest.raises(LearningLoopError, match="OBSERVER_TRUST_ROOT_IN_WORKSPACE"):
        validate_instruction_candidate(
            Path(candidate["path"]),
            tmp_path,
            "specialty-ai:cf-reviewer",
            results,
            observer_trust_root=in_workspace,
        )


def test_forensic_observer_rejects_missing_gates_and_mismatched_outcome(tmp_path: Path):
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}\n", encoding="utf-8")
    packet = seal_forensic_rejection_packet(
        tmp_path,
        {
            "schema": "factory.forensic-rejection.v1",
            "candidate_sha256": "a" * 64,
            "source_sha256": "b" * 64,
            "failure_class": "policy_breach",
            "failure_id": "complexity",
            "failed_mutation_seeds": [],
            "policy_breaches": [
                {
                    "id": "breach",
                    "rule_id": "complexity-10",
                    "severity": "high",
                    "evidence_id": "audit",
                }
            ],
            "counterfactual_profiles": [],
            "review_corrections": [],
            "validator_versions": [{"name": "forge", "version": "1"}],
            "evidence_bindings": [
                {
                    "id": "audit",
                    "kind": "audit",
                    "path": str(evidence),
                    "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                }
            ],
            "unknowns": [],
        },
    )
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet), encoding="utf-8")
    task = init_learning_task(
        tmp_path, "observer", "owner", "Fix complexity", MILESTONES
    )
    outcome = tmp_path / "outcome.json"
    outcome.write_text(
        json.dumps({"candidate_sha256": "a" * 64, "source_sha256": "b" * 64}),
        encoding="utf-8",
    )
    with pytest.raises(LearningLoopError, match="OBSERVER_GATES_INCOMPLETE"):
        propose_instruction_candidate(
            Path(task["path"]),
            tmp_path,
            "spec",
            "observer",
            outcome,
            [{"dimension": "d4_orchestration", "instruction": "Split decisions."}],
            forensic_packet_path=packet_path,
        )


def test_asha_experiment_is_correctness_first_and_has_no_execution_authority(
    tmp_path: Path,
):
    task = init_learning_task(
        tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES
    )
    plan = plan_learning_experiment(
        Path(task["path"]),
        {
            "d1_context_assembly": ["compact", "retrieval"],
            "d4_orchestration": ["plan-execute", "plan-refine"],
        },
        variant="asha",
        max_resource=50,
        grace_period=5,
        reduction_factor=3,
    )
    assert plan["scheduler"]["asynchronous"] is True
    assert plan["objective"]["primary"] == {
        "metric": "correctness",
        "mode": "max",
        "required": True,
        "range": [0.0, 1.0],
    }
    assert plan["authority"] == {
        "execute": False,
        "read_credentials": False,
        "train": False,
        "promote": False,
    }


def test_experiment_rejects_unknown_dimensions_and_unbounded_budget(tmp_path: Path):
    task = init_learning_task(
        tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES
    )
    with pytest.raises(LearningLoopError, match="SEARCH_SPACE_INVALID"):
        plan_learning_experiment(Path(task["path"]), {"prompt_magic": [True]})
    with pytest.raises(LearningLoopError, match="SEARCH_BUDGET_INVALID"):
        plan_learning_experiment(
            Path(task["path"]),
            {"d1_context_assembly": ["compact"]},
            max_concurrent=1001,
        )


def test_milestone_order_is_fail_closed(tmp_path: Path):
    task = init_learning_task(
        tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES
    )
    with pytest.raises(LearningLoopError, match="MILESTONE_ORDER_BLOCKED"):
        build_fresh_worker_packet(Path(task["path"]), "runtime", "worker-2")


def test_promotion_rechecks_evidence_hashes(tmp_path: Path):
    _task, candidate, evidence = _candidate(tmp_path)
    validation = validate_instruction_candidate(
        Path(candidate["path"]),
        tmp_path,
        "validator",
        [{"id": "requirements", "passed": True, "evidence": [str(evidence)]}],
    )
    evidence.write_text('{"valid": false}\n', encoding="utf-8")
    with pytest.raises(LearningLoopError, match="HASH_INVALID"):
        promote_instruction_candidate(Path(validation["path"]), "owner")


def test_cli_runs_complete_learning_lane(tmp_path: Path, capsys):
    milestones = tmp_path / "milestones.json"
    milestones.write_text(json.dumps(MILESTONES), encoding="utf-8")
    assert (
        main(
            [
                "learning",
                "init",
                "checkout",
                "--root",
                str(tmp_path),
                "--owner",
                "owner",
                "--objective",
                "Ship verified checkout",
                "--milestones",
                str(milestones),
                "--json",
            ]
        )
        == 0
    )
    task = json.loads(capsys.readouterr().out)

    outcome = tmp_path / "outcome.json"
    outcome.write_text('{"requirements": "passed"}\n', encoding="utf-8")
    instructions = tmp_path / "instructions.json"
    instructions.write_text(
        json.dumps(
            [
                {
                    "dimension": "d6_output_processing",
                    "instruction": "Run strict validation.",
                }
            ]
        ),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "learning",
                "propose",
                task["path"],
                "--root",
                str(tmp_path),
                "--milestone",
                "spec",
                "--worker",
                "worker",
                "--outcome",
                str(outcome),
                "--instructions",
                str(instructions),
                "--json",
            ]
        )
        == 0
    )
    candidate = json.loads(capsys.readouterr().out)

    evidence = tmp_path / "evidence.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    results = tmp_path / "results.json"
    results.write_text(
        json.dumps(
            [{"id": "requirements", "passed": True, "evidence": [str(evidence)]}]
        ),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "learning",
                "validate",
                candidate["path"],
                "--root",
                str(tmp_path),
                "--validator",
                "validator",
                "--results",
                str(results),
                "--json",
            ]
        )
        == 0
    )
    validation = json.loads(capsys.readouterr().out)
    assert (
        main(["learning", "promote", validation["path"], "--owner", "owner", "--json"])
        == 0
    )
    promotion = json.loads(capsys.readouterr().out)
    assert promotion["aku"]["procedure"] == ["Run strict validation."]
