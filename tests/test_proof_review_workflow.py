from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import pytest
from factoryline.cli import main
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.proof_reuse import record_proof
from factoryline.proof_review_workflow import (
    ProofReviewError,
    create_intent_contract,
    create_proof_card,
    create_quick_review,
    install_hook_pack,
    promote_regression,
    prove_trajectory,
    team_proof_inbox,
    verify_intent_contract,
    verify_proof_card,
    verify_quick_review,
    verify_trajectory,
)
from test_intake_admission import _intake
import hashlib
from factoryline.contract import sha_of
from factoryline.deep_audit_io import bound_bytes, source_language
from factoryline.deep_audit_loop import deep_scan_projection
from factoryline.domain_ontology import domain_ontology_template
from factoryline.enterprise_receipts import dsse_pae
from factoryline.lifecycle_ledger import lifecycle_template
from factoryline.operations_control import operations_control_template
from factoryline.passport import mermaid_for
from factoryline.privacy import PrivacyError, merkle_root
from factoryline.proof_review_workflow import proof_review_projection
from factoryline.protocol import version_tuple
from factoryline.release_contract import release_readiness_projection
from factoryline.repair_loop import repair_loop_template
from factoryline.revenue_evidence import revenue_evidence_projection
from factoryline.repo_coordination import repo_coordination_template
from factoryline.service_boundaries import service_boundary_template
from factoryline.continuous_proof import continuous_proof_projection
from factoryline.judgment import judgment_projection
import time
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
from factoryline.live_feedback import (
    LiveFeedbackError,
    load_live_json,
    validate_live_manifest,
)
from factoryline.ops_telemetry import record_lifecycle
from factoryline.receipt_index import indexed_receipt_paths
from factoryline.refinement import pareto_win
from factoryline.run_metrics import export_public_metrics, load_run_receipts
from factoryline.savings import load_savings_pairs
from factoryline.update_notifier import read_manifest


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _workspace(root: Path) -> tuple[Path, Path]:
    changed = root / "src" / "service.py"
    changed.parent.mkdir(parents=True, exist_ok=True)
    changed.write_text("answer = 42\n", encoding="utf-8")
    output = root / "proof.txt"
    output.write_text("passed\n", encoding="utf-8")
    _write_json(
        root / "coverage" / "requirements.json",
        {"requirements": [{"id": "REQ_SERVICE"}]},
    )
    _write_json(
        root / "smoke" / "service.json",
        {"checks": [{"covers": ["REQ_SERVICE"], "must_fail_on_stub": True}]},
    )
    record_proof(
        root,
        {
            "name": "service-unit",
            "command": ["python", "-m", "pytest"],
            "read_only": True,
            "inputs": ["src/service.py"],
            "outputs": ["proof.txt"],
        },
        elapsed_ms=10,
        replace=True,
    )
    draft = _write_json(
        root / "intent-draft.json",
        {
            "outcome": "Return the declared answer.",
            "acceptance": ["The service returns 42."],
            "rejection": ["The service returns any other value."],
            "validators": ["service-unit"],
            "allowed_paths": ["src"],
            "non_goals": ["Deploy the service."],
        },
    )
    return changed, draft


def _contract(root: Path, contract_id: str = "service-intent") -> dict:
    _, draft = _workspace(root)
    return create_intent_contract(root, contract_id, draft, "Reviewer One")


def _session(root: Path, *, passed: bool) -> Path:
    directory = (
        root
        / ".factory"
        / "session-recorder"
        / ("passed-run" if passed else "failed-run")
    )
    directory.mkdir(parents=True, exist_ok=True)
    result_path = directory / "result.json"
    result_path.write_bytes(
        _canonical(
            {
                "schema": "factory.session-recorder.result.v1",
                "workspace_delta": [
                    {
                        "path": "src/service.py",
                        "status": "modified",
                        "after_sha256": _sha(root / "src" / "service.py"),
                    }
                ],
            }
        )
        + b"\n"
    )
    verification_path = directory / "verification.json"
    verification_path.write_bytes(
        _canonical(
            {"schema": "factory.session-recorder.validation.v1", "passed": passed}
        )
        + b"\n"
    )
    core = {
        "schema": "factory.observed-session.v1",
        "marker": "OBSERVED_SESSION_RECORDED",
        "run_id": directory.name,
        "recorded_at": "2026-08-29T12:00:00Z",
        "previous_session_sha256": None,
        "result": {
            "path": result_path.relative_to(root).as_posix(),
            "sha256": _sha(result_path),
        },
        "verification": {
            "path": verification_path.relative_to(root).as_posix(),
            "sha256": _sha(verification_path),
        },
        "agent_event": {
            "path": ".factory/agent-licenses/events/fake.json",
            "sha256": "0" * 64,
        },
        "passed": passed,
        "failure_classes": [] if passed else ["wrong_output"],
        "authority": {},
        "scope_limits": [],
    }
    receipt = {**core, "session_sha256": sha256(_canonical(core)).hexdigest()}
    path = directory / "session.json"
    path.write_bytes(_canonical(receipt) + b"\n")
    return path


def _trajectory(
    root: Path, trajectory_id: str = "agent-run", *, independent: bool = True
) -> dict:
    trace = _write_json(
        root / f"{trajectory_id}-trace.json",
        {
            "worker_actor": "worker",
            "events": [
                {"type": "intent_loaded", "actor": "worker"},
                {
                    "type": "tool_used",
                    "actor": "worker",
                    "tool": "editor",
                    "path": "src/service.py",
                },
                {"type": "validation_observed", "actor": "worker", "tool": "pytest"},
                {
                    "type": "independent_audit",
                    "actor": "verifier" if independent else "worker",
                },
            ],
        },
    )
    policy = _write_json(
        root / f"{trajectory_id}-policy.json",
        {
            "max_steps": 20,
            "required_events": [
                "intent_loaded",
                "tool_used",
                "validation_observed",
                "independent_audit",
            ],
            "allowed_tools": ["editor", "pytest"],
            "forbidden_tools": ["deploy"],
            "allowed_paths": ["src"],
        },
    )
    return prove_trajectory(root, trace, policy, trajectory_id)


def test_req_pr_001_intent_contract_is_complete_confirmed_bound_and_immutable(
    tmp_path: Path,
) -> None:
    contract = _contract(tmp_path)
    assert verify_intent_contract(tmp_path, Path(contract["artifact"]))["ok"] is True
    assert contract["human_confirmed"] is True and contract["final_approval"] is False
    with pytest.raises(ProofReviewError, match="immutable"):
        create_intent_contract(
            tmp_path, "service-intent", tmp_path / "intent-draft.json", "Reviewer One"
        )
    (tmp_path / "intent-draft.json").write_text("{}", encoding="utf-8")
    assert (
        verify_intent_contract(tmp_path, Path(contract["artifact"]))["marker"]
        == "INTENT_CONTRACT_STALE"
    )


def test_req_pr_002_five_minute_review_has_exact_fail_closed_routes(
    tmp_path: Path,
) -> None:
    contract = _contract(tmp_path)
    missing = create_quick_review(
        tmp_path, "missing-evidence", Path(contract["artifact"]), ["src/service.py"]
    )
    assert missing["route"] == "evidence_required"
    passed = create_quick_review(
        tmp_path,
        "passing-evidence",
        Path(contract["artifact"]),
        ["src/service.py"],
        session_path=_session(tmp_path, passed=True),
    )
    assert passed["route"] == "review_ready"
    assert passed["final_approval"] is False
    assert verify_quick_review(tmp_path, Path(passed["artifact"]))["ok"] is True


def test_req_pr_003_hook_pack_writes_five_templates_without_vendor_mutation(
    tmp_path: Path,
) -> None:
    vendor = _write_json(tmp_path / ".cursor" / "hooks.json", {"keep": True})
    before = vendor.read_bytes()
    pack = install_hook_pack(tmp_path)
    assert pack["adapters"] == [
        "github-copilot",
        "claude-code",
        "codex",
        "cursor",
        "generic-jsonl",
    ]
    assert pack["installed_vendor_config"] is False and vendor.read_bytes() == before
    target = tmp_path / ".factory" / "proof-review" / "hooks" / "cursor.json"
    target.write_text("changed", encoding="utf-8")
    with pytest.raises(ProofReviewError, match="refusing to overwrite"):
        install_hook_pack(tmp_path)


def test_req_pr_004_failure_learning_requires_human_and_is_immutable(
    tmp_path: Path,
) -> None:
    contract = _contract(tmp_path)
    failed = create_quick_review(
        tmp_path,
        "failed-evidence",
        Path(contract["artifact"]),
        ["src/service.py"],
        session_path=_session(tmp_path, passed=False),
    )
    with pytest.raises(ProofReviewError, match="named confirmer"):
        promote_regression(
            tmp_path, Path(failed["artifact"]), "wrong-answer", "", "Wrong answer"
        )
    capsule = promote_regression(
        tmp_path,
        Path(failed["artifact"]),
        "wrong-answer",
        "Reviewer Two",
        "Wrong answer",
    )
    assert (
        capsule["failure_classes"] == ["wrong_output"]
        and capsule["human_confirmed"] is True
    )
    with pytest.raises(ProofReviewError, match="immutable"):
        promote_regression(
            tmp_path,
            Path(failed["artifact"]),
            "wrong-answer",
            "Reviewer Two",
            "Wrong answer",
        )


def test_req_pr_005_team_inbox_prioritizes_human_work_and_keeps_claim_limits(
    tmp_path: Path,
) -> None:
    contract = _contract(tmp_path)
    create_quick_review(
        tmp_path, "needs-evidence", Path(contract["artifact"]), ["src/service.py"]
    )
    create_quick_review(
        tmp_path,
        "failed-evidence",
        Path(contract["artifact"]),
        ["src/service.py"],
        session_path=_session(tmp_path, passed=False),
    )
    inbox = team_proof_inbox(tmp_path)
    assert (
        inbox["current_count"] == 2 and inbox["next_item"]["route"] == "human_required"
    )
    assert "not unique users" in inbox["claim_limits"][0]


def test_req_pr_006_trajectory_enforces_order_scope_tools_and_independent_audit(
    tmp_path: Path,
) -> None:
    _workspace(tmp_path)
    passed = _trajectory(tmp_path)
    assert (
        passed["passed"] is True
        and verify_trajectory(tmp_path, Path(passed["artifact"]))["passed"] is True
    )
    failed = _trajectory(tmp_path, "self-audited", independent=False)
    assert failed["passed"] is False
    assert "independent_audit" in {item["kind"] for item in failed["violations"]}


def test_req_pr_007_card_is_public_safe_and_offline_tamper_evident(
    tmp_path: Path,
) -> None:
    contract = _contract(tmp_path)
    review = create_quick_review(
        tmp_path, "card-review", Path(contract["artifact"]), ["src/service.py"]
    )
    card = create_proof_card(tmp_path, Path(review["artifact"]), "public-card")
    assert set(card["artifacts"]) == {"json", "markdown", "svg"}
    assert verify_proof_card(Path(card["artifacts"]["json"]))["ok"] is True
    path = Path(card["artifacts"]["json"])
    value = json.loads(path.read_text(encoding="utf-8"))
    value["route"] = "review_ready"
    path.write_text(json.dumps(value), encoding="utf-8")
    assert verify_proof_card(path)["ok"] is False


def test_req_pr_008_graph_ops_projects_read_only_team_inbox(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    create_quick_review(
        tmp_path, "graph-review", Path(contract["artifact"]), ["src/service.py"]
    )
    snapshot = graph_ops_snapshot(tmp_path)
    assert snapshot["proof_review"]["current_count"] == 1
    assert snapshot["facts"]["proof_review_current_count"] == 1
    assert "GRAPH_OPS_PROOF_REVIEW_READ_ONLY" in snapshot["markers"]


def test_req_pr_009_paths_are_workspace_contained_and_large_inputs_fail_closed(
    tmp_path: Path,
) -> None:
    _workspace(tmp_path)
    outside = tmp_path.parent / "outside-intent.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(ProofReviewError, match="inside the workspace"):
        create_intent_contract(tmp_path, "outside", outside, "Reviewer")
    large = tmp_path / "large.json"
    large.write_bytes(b"x" * 1_048_577)
    with pytest.raises(ProofReviewError, match="no larger"):
        create_intent_contract(tmp_path, "large", large, "Reviewer")


def test_req_pr_010_cli_is_one_machine_readable_front_door_without_regression(
    tmp_path: Path, capsys
) -> None:
    _, draft = _workspace(tmp_path)
    assert (
        main(
            [
                "proof-review",
                "contract",
                "--root",
                str(tmp_path),
                "--id",
                "cli-intent",
                "--draft",
                str(draft),
                "--confirmed-by",
                "Reviewer",
                "--json",
            ]
        )
        == 0
    )
    contract = json.loads(capsys.readouterr().out)
    assert (
        main(
            [
                "proof-review",
                "quick",
                "--root",
                str(tmp_path),
                "--id",
                "cli-review",
                "--contract",
                contract["artifact"],
                "--changed",
                "src/service.py",
                "--json",
            ]
        )
        == 0
    )
    review = json.loads(capsys.readouterr().out)
    assert review["route"] == "evidence_required"
    assert (
        main(
            [
                "proof-review",
                "verify",
                review["artifact"],
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_strict_proof_review_binds_intake_scope_and_digest(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    intake_path, _ = _intake(tmp_path, scope=["src"])
    review = create_quick_review(
        tmp_path,
        "intake-bound-review",
        Path(contract["artifact"]),
        ["src/service.py"],
        intake_parameters_path=intake_path,
        require_intake=True,
    )
    checked = verify_quick_review(tmp_path, Path(review["artifact"]))
    assert checked["ok"] is True
    value = json.loads(Path(review["artifact"]).read_text(encoding="utf-8"))
    assert value["intake_parameters"]["parameter_sha256"]


def test_strict_proof_review_rejects_missing_intake(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    with pytest.raises(ProofReviewError) as raised:
        create_quick_review(
            tmp_path,
            "strict-review",
            Path(contract["artifact"]),
            ["src/service.py"],
            require_intake=True,
        )
    assert raised.value.code == "E_INTAKE_BINDING_REQUIRED"


# Consolidated tests from tests/test_attribution_io.py


@pytest.mark.parametrize(
    "template",
    [
        domain_ontology_template,
        lifecycle_template,
        operations_control_template,
        repair_loop_template,
        repo_coordination_template,
        service_boundary_template,
    ],
)
def test_empty_templates_are_versioned_and_authority_free(template):
    value = template()

    assert value["schema"].startswith("factory.")
    assert value["claim_boundary"]
    assert all(flag is False for flag in value["authority"].values())


@pytest.mark.parametrize(
    "projection",
    [
        proof_review_projection,
        revenue_evidence_projection,
        continuous_proof_projection,
        judgment_projection,
        release_readiness_projection,
    ],
)
def test_empty_projections_report_no_local_evidence_or_authority(projection, tmp_path):
    value = projection(tmp_path)

    assert value["authority"]
    assert all(flag is False for flag in value["authority"].values())
    assert value.get("count", value.get("contract_count", 0)) == 0


def test_deep_scan_projection_marks_unrun_state_without_promoting_assurance(tmp_path):
    value, _ = deep_scan_projection(tmp_path)

    assert value["state"] == "NOT_RUN"
    assert value["analysis_complete"] is False
    assert value["authority"] == "none"


def test_sha_of_tracks_exact_bytes_and_absent_files(tmp_path):
    source = tmp_path / "source.py"
    source.write_bytes(b"value = 1\n")

    assert sha_of(source) == hashlib.sha256(source.read_bytes()).hexdigest()[:16]
    assert sha_of(tmp_path / "missing.py") == ""


def test_version_tuple_parses_release_components_and_rejects_invalid_versions():
    assert version_tuple("1.2.3") == (1, 2, 3)
    assert version_tuple("release 2-beta 4") == (2, 4)
    assert version_tuple("no digits") == (0,)


def test_merkle_root_is_order_independent_and_rejects_empty_commitments():
    assert merkle_root(["alpha", "beta"]) == merkle_root(["beta", "alpha"])
    assert merkle_root(["alpha", "beta"]) != merkle_root(["alpha", "gamma"])
    with pytest.raises(PrivacyError):
        merkle_root([])


def test_mermaid_for_emits_challenge_nodes_into_a_compact_proof_graph():
    graph = mermaid_for(
        {"challenges": [{"brick": "forge", "mutants_killed": 3, "mutants_total": 4}]}
    )

    assert "flowchart LR" in graph
    assert "forge: 3/4 rejected" in graph
    assert 'C1 --> P["Factory Passport"]' in graph


def test_dsse_pae_uses_utf8_byte_lengths_and_exact_payload_bytes():
    assert dsse_pae("t", b"x") == b"DSSEv1 1 t 1 x"
    encoded = dsse_pae("application/test", b"\x00\xff")
    assert encoded.startswith(b"DSSEv1 16 application/test 2 ")
    assert encoded.endswith(b"\x00\xff")


def test_source_language_classification_does_not_promote_unknown_formats():
    assert source_language("worker.py", b"print('ok')") == "python"
    assert source_language("launch.sh", b"#!/bin/sh\ntrue") == "shell"
    assert source_language("payload.bin", b"\x00\x01") == "unknown"


def test_bound_bytes_requires_matching_hash_and_workspace_containment(tmp_path):
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(b'{"state":"PASS"}')
    binding = {
        "path": "evidence.json",
        "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
    }

    assert bound_bytes(tmp_path, binding) == evidence.read_bytes()
    with pytest.raises(Exception, match="E_REPORT_DRIFT"):
        bound_bytes(tmp_path, {**binding, "sha256": "0" * 64})
    with pytest.raises(Exception, match="E_PATH_ESCAPE"):
        bound_bytes(tmp_path, {**binding, "path": "../outside.json"})


def test_proof_review_and_continuity_projections_stay_empty_without_receipts(tmp_path):
    review = proof_review_projection(tmp_path)
    continuity = continuous_proof_projection(tmp_path)
    revenue = revenue_evidence_projection(tmp_path)
    judgment = judgment_projection(tmp_path)
    readiness = release_readiness_projection(tmp_path)

    assert review["current_count"] == review["stale_count"] == 0
    assert continuity["current_count"] == continuity["stale_count"] == 0
    assert revenue["replay"]["count"] == 0
    assert judgment["status"] == "empty"
    assert readiness["contract_count"] == 0


# Consolidated tests from tests/test_attribution_workflows.py
"""Behavior-focused tests for local workflow and projection entry points."""


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
    assert (
        encoded
        == json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")).encode()
    )


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


def test_lifecycle_writer_excludes_raw_arguments_and_workspace_paths(
    tmp_path: Path,
) -> None:
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


def test_savings_pair_loader_ignores_malformed_and_foreign_files(
    tmp_path: Path,
) -> None:
    pair_dir = tmp_path / ".factory" / "savings"
    pair_dir.mkdir(parents=True)
    (pair_dir / "broken.json").write_text("{", encoding="utf-8")
    (pair_dir / "foreign.json").write_text('{"schema":"foreign.v1"}', encoding="utf-8")

    assert load_savings_pairs(tmp_path) == []


def test_live_activity_stage_completion_updates_only_observed_counts(
    tmp_path: Path,
) -> None:
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
