from __future__ import annotations
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import pytest
from factoryline.cli import main
from factoryline.continuity import (
    ContinuityError,
    ContinuityPrincipal,
    ContinuityStore,
    continuity_projection,
    principal_from_args,
    promote_continuity,
    recall_continuity,
    record_continuity,
)
from factoryline.graph_ops import graph_ops_html, graph_ops_snapshot
import hashlib
from factoryline.continuous_controls import (
    ControlsError,
    build_control_graph,
    continuous_controls_projection,
    create_exception,
    evaluate_controls,
    fleet_coverage,
    load_policy_pack,
    render_controls_review,
    verify_control_evaluation,
    write_control_evaluation,
    write_controls_dossier,
)
from io import BytesIO
from factoryline.control_plane import (
    ControlPlaneError,
    EvidenceStore,
    Principal,
    authorize,
)
from factoryline.control_api import ControlPlaneAPI
from factoryline.live_activity import LiveActivity, activity_snapshot, request_stop
from hashlib import sha256
from factoryline.mission_graph import (
    MissionGraphError,
    apply_mission_event,
    build_langgraph_adapter,
    export_mission_graph,
    init_mission_graph,
    langgraph_doctor,
    mission_graph_history,
    mission_graph_status,
    recommend_mission_route,
    verify_mission_graph,
)
from factoryline.product_missions import (
    close_mission,
    compile_product_prd,
    create_mission,
    decide_mission,
    plan_value_slices,
)
from factoryline.proof_delta import create_proof_delta
import subprocess
import time
from factoryline.audit_trace import build_audit_trace
from factoryline.control_plane import canonical_json
from factoryline.operations import (
    CanaryPolicy,
    OperationsError,
    TelemetryRecorder,
    connector_event,
    evaluate_canary,
    evaluate_judge_calibration,
    measured_span,
    rollback_receipt,
    vulnerability_response,
)

PURPOSE = "delivery-review@1"
SCOPE = "repo:sha256:abc123"


def _principal(subject: str, roles: tuple[str, ...]) -> ContinuityPrincipal:
    return ContinuityPrincipal(
        subject=subject, tenant_id="tenant-a", roles=roles, purposes=(PURPOSE,)
    )


def _record(*, scope: str = SCOPE, expires_at: str | None = None) -> dict:
    return {
        "schema": "factory.continuity.record.v1",
        "tenant_id": "tenant-a",
        "record_type": "decision",
        "memory_ref": "memory://engineering/adr-0042",
        "purpose": {"id": "delivery-review", "version": "1"},
        "scope": {"repository_ref": scope},
        "evidence_refs": ["receipt:sha256:proof-001", "adr:0042"],
        "summary": "Prefer the verified migration path until the dependency contract changes.",
        "expires_at": expires_at
        or (datetime.now(timezone.utc) + timedelta(days=3)).isoformat(),
    }


def test_continuity_requires_independent_promotion_and_exact_scope_purpose(
    tmp_path: Path,
):
    store = ContinuityStore(tmp_path / "continuity.sqlite3")
    created = store.record(
        _principal("worker", ("writer",)),
        _record(),
        idempotency_key="intent-1",
        record_id="record-1",
    )
    assert created["status"] == "draft"

    before = store.recall(
        _principal("reader", ("reader",)),
        "tenant-a",
        purpose_ref=PURPOSE,
        scope_ref=SCOPE,
    )
    assert before["records"] == []

    with pytest.raises(ContinuityError) as self_promotion:
        store.promote(
            _principal("worker", ("promoter",)),
            "tenant-a",
            "record-1",
            reason="self review",
        )
    assert self_promotion.value.code == "E_SELF_PROMOTION"

    promoted = store.promote(
        _principal("reviewer", ("promoter",)),
        "tenant-a",
        "record-1",
        reason="receipt and ADR independently reviewed",
    )
    assert promoted["status"] == "verified"
    assert promoted["promoted_by"] == "reviewer"

    recalled = store.recall(
        _principal("reader", ("reader",)),
        "tenant-a",
        purpose_ref=PURPOSE,
        scope_ref=SCOPE,
    )
    assert recalled["marker"] == "CONTINUITY_RECALL_SCOPE_AND_PURPOSE_EXACT"
    assert [item["record_id"] for item in recalled["records"]] == ["record-1"]

    wrong_scope = store.recall(
        _principal("reader", ("reader",)),
        "tenant-a",
        purpose_ref=PURPOSE,
        scope_ref="repo:sha256:other",
    )
    assert wrong_scope["records"] == []
    wrong_purpose = ContinuityPrincipal(
        "reader", "tenant-a", ("reader",), ("incident-response@1",)
    )
    with pytest.raises(ContinuityError) as denied:
        store.recall(wrong_purpose, "tenant-a", purpose_ref=PURPOSE, scope_ref=SCOPE)
    assert denied.value.code == "E_PURPOSE_DENIED"


def test_continuity_rejects_content_store_and_conflicting_idempotency(tmp_path: Path):
    store = ContinuityStore(tmp_path / "continuity.sqlite3")
    payload = _record()
    payload["content"] = "do not put source or memory bodies in this ledger"
    with pytest.raises(ContinuityError) as forbidden:
        store.record(
            _principal("writer", ("writer",)), payload, idempotency_key="content"
        )
    assert forbidden.value.code == "E_CONTENT_STORE_FORBIDDEN"

    stable_payload = _record()
    saved = store.record(
        _principal("writer", ("writer",)),
        stable_payload,
        idempotency_key="stable",
        record_id="stable-record",
    )
    replay = store.record(
        _principal("writer", ("writer",)),
        stable_payload,
        idempotency_key="stable",
        record_id="stable-record",
    )
    assert replay["record_sha256"] == saved["record_sha256"]
    changed = _record(scope="repo:sha256:changed")
    with pytest.raises(ContinuityError) as conflict:
        store.record(
            _principal("writer", ("writer",)), changed, idempotency_key="stable"
        )
    assert conflict.value.code == "E_IDEMPOTENCY_CONFLICT"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", "wrong.schema.v1"),
        ("tenant_id", ""),
        ("record_type", "unsupported"),
        ("memory_ref", ""),
        ("purpose", {"id": "delivery-review"}),
        ("scope", {}),
        ("evidence_refs", []),
        ("expires_at", "2020-01-01T00:00:00Z"),
    ],
)
def test_continuity_rejects_incomplete_metadata_before_any_record_or_audit_write(
    tmp_path: Path, field: str, value: object
):
    db_path = tmp_path / "continuity.sqlite3"
    store = ContinuityStore(db_path)
    payload = _record()
    payload[field] = value
    with pytest.raises(ContinuityError):
        store.record(
            _principal("writer", ("writer",)),
            payload,
            idempotency_key=f"invalid-{field}",
        )
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM continuity_records").fetchone()[0] == 0
        assert (
            db.execute("SELECT COUNT(*) FROM continuity_audit_events").fetchone()[0]
            == 0
        )

    with pytest.raises(ContinuityError) as missing_idempotency:
        store.record(_principal("writer", ("writer",)), _record(), idempotency_key="")
    assert missing_idempotency.value.code == "E_IDEMPOTENCY_REQUIRED"


def test_continuity_record_rolls_back_when_the_audit_append_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    db_path = tmp_path / "continuity.sqlite3"
    store = ContinuityStore(db_path)

    def fail_audit(*_args, **_kwargs):
        raise RuntimeError("simulated audit storage failure")

    monkeypatch.setattr(store, "_audit", fail_audit)
    with pytest.raises(RuntimeError, match="simulated audit storage failure"):
        store.record(
            _principal("writer", ("writer",)), _record(), idempotency_key="rollback"
        )
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM continuity_records").fetchone()[0] == 0
        assert (
            db.execute("SELECT COUNT(*) FROM continuity_audit_events").fetchone()[0]
            == 0
        )


def test_continuity_promotion_rejects_tenant_purpose_expiry_and_repeat_attempts(
    tmp_path: Path,
):
    db_path = tmp_path / "continuity.sqlite3"
    store = ContinuityStore(db_path)
    store.record(
        _principal("writer", ("writer",)),
        _record(),
        idempotency_key="promotion",
        record_id="promotion-record",
    )

    other_tenant = ContinuityPrincipal(
        "reviewer", "tenant-b", ("promoter",), (PURPOSE,)
    )
    with pytest.raises(ContinuityError) as denied_tenant:
        store.promote(
            other_tenant, "tenant-a", "promotion-record", reason="cross-tenant"
        )
    assert denied_tenant.value.code == "E_TENANT_BOUNDARY"

    wrong_purpose = ContinuityPrincipal(
        "reviewer", "tenant-a", ("promoter",), ("incident-response@1",)
    )
    with pytest.raises(ContinuityError) as denied_purpose:
        store.promote(
            wrong_purpose, "tenant-a", "promotion-record", reason="wrong-purpose"
        )
    assert denied_purpose.value.code == "E_PURPOSE_DENIED"

    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE continuity_records SET expires_at = ? WHERE record_id = ?",
            ("2020-01-01T00:00:00Z", "promotion-record"),
        )
        db.commit()
    with pytest.raises(ContinuityError) as expired:
        store.promote(
            _principal("reviewer", ("promoter",)),
            "tenant-a",
            "promotion-record",
            reason="expired",
        )
    assert expired.value.code == "E_RECORD_EXPIRED"

    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE continuity_records SET expires_at = ? WHERE record_id = ?",
            (_record()["expires_at"], "promotion-record"),
        )
        db.commit()
    store.promote(
        _principal("reviewer", ("promoter",)),
        "tenant-a",
        "promotion-record",
        reason="valid",
    )
    with pytest.raises(ContinuityError) as repeat:
        store.promote(
            _principal("second-reviewer", ("promoter",)),
            "tenant-a",
            "promotion-record",
            reason="again",
        )
    assert repeat.value.code == "E_ALREADY_PROMOTED"


def test_continuity_withholds_expired_records_and_detects_audit_tampering(
    tmp_path: Path,
):
    db_path = tmp_path / "continuity.sqlite3"
    store = ContinuityStore(db_path)
    store.record(
        _principal("writer", ("writer",)),
        _record(),
        idempotency_key="expires",
        record_id="expiring",
    )
    store.promote(
        _principal("reviewer", ("promoter",)), "tenant-a", "expiring", reason="reviewed"
    )
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE continuity_records SET expires_at = ? WHERE record_id = ?",
            ("2020-01-01T00:00:00Z", "expiring"),
        )
        db.commit()
    recalled = store.recall(
        _principal("reader", ("reader",)),
        "tenant-a",
        purpose_ref=PURPOSE,
        scope_ref=SCOPE,
    )
    assert recalled["records"] == []
    assert recalled["withheld_expired_record_ids"] == ["expiring"]

    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE continuity_audit_events SET payload_json = ?",
            (json.dumps({"tampered": True}),),
        )
        db.commit()
    proof = store.prove(_principal("reader", ("reader",)), "tenant-a", "expiring")
    assert proof["audit"]["valid"] is False


def test_graph_ops_projects_redacted_continuity_metadata_without_writing(
    tmp_path: Path,
):
    db_path = tmp_path / ".factory" / "continuity.sqlite3"
    store = ContinuityStore(db_path)
    store.record(
        _principal("worker", ("writer",)),
        _record(),
        idempotency_key="graph",
        record_id="graph-record",
    )
    store.promote(
        _principal("reviewer", ("promoter",)),
        "tenant-a",
        "graph-record",
        reason="reviewed",
    )
    before = db_path.read_bytes()
    graph = graph_ops_snapshot(tmp_path)
    after = db_path.read_bytes()
    assert after == before
    assert "GRAPH_OPS_CONTINUITY_METADATA_READ_ONLY" in graph["markers"]
    assert graph["facts"]["continuity_verified_current_count"] == 1
    record = next(
        item for item in graph["nodes"] if item["id"] == "continuity:graph-record"
    )
    assert "memory_ref" not in record["facts"]
    assert "summary" not in record["facts"]
    assert graph["authority"]["publication"] is False
    page = graph_ops_html("local-token")
    assert "Factory Continuity · Decision Replay" in page
    assert "memory contents displayed" in page
    assert "promote-continuity" in page and "disabled" in page


def test_continuity_projection_is_bounded_redacted_and_principal_args_normalize(
    tmp_path: Path,
):
    db_path = tmp_path / ".factory" / "continuity.sqlite3"
    store = ContinuityStore(db_path)
    store.record(
        _principal("writer", ("writer",)),
        _record(),
        idempotency_key="projected",
        record_id="projected",
    )
    projection = continuity_projection(tmp_path)
    principal = principal_from_args(
        "reader", "tenant-a", ["reader", " reader "], [PURPOSE, " "]
    )
    assert principal.roles == ("reader",)
    assert principal.purposes == (PURPOSE,)
    assert projection["available"] is True
    assert projection["records"][0]["record_id"] == "projected"
    assert projection["records"][0]["effective_status"] == "draft"
    assert "memory_ref" not in projection["records"][0]
    assert "summary" not in projection["records"][0]


def test_top_level_continuity_adapters_keep_the_store_as_the_single_boundary(
    tmp_path: Path,
):
    store = ContinuityStore(tmp_path / "continuity.sqlite3")
    writer = _principal("writer", ("writer",))
    record = record_continuity(store, writer, _record(), "adapter-record")
    promoted = promote_continuity(
        store,
        _principal("reviewer", ("promoter",)),
        "tenant-a",
        record["record_id"],
        "reviewed",
    )
    recalled = recall_continuity(
        store, _principal("reader", ("reader",)), "tenant-a", PURPOSE, SCOPE
    )
    assert promoted["status"] == "verified"
    assert recalled["records"][0]["record_id"] == record["record_id"]


def test_cli_continuity_flow_is_local_and_explicit(tmp_path: Path, capsys):
    db = tmp_path / "continuity.sqlite3"
    payload = tmp_path / "record.json"
    payload.write_text(json.dumps(_record()), encoding="utf-8")
    assert main(["continuity", "init", "--db", str(db)]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "continuity",
                "record",
                str(payload),
                "--idempotency-key",
                "cli-1",
                "--record-id",
                "cli-record",
                "--db",
                str(db),
                "--tenant",
                "tenant-a",
                "--subject",
                "worker",
                "--roles",
                "writer",
                "--purposes",
                PURPOSE,
            ]
        )
        == 0
    )
    created = json.loads(capsys.readouterr().out)
    assert created["status"] == "draft"
    assert (
        main(
            [
                "continuity",
                "promote",
                "cli-record",
                "--reason",
                "independent review",
                "--db",
                str(db),
                "--tenant",
                "tenant-a",
                "--subject",
                "reviewer",
                "--roles",
                "promoter",
                "--purposes",
                PURPOSE,
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            [
                "continuity",
                "recall",
                "--purpose",
                PURPOSE,
                "--scope",
                SCOPE,
                "--db",
                str(db),
                "--tenant",
                "tenant-a",
                "--subject",
                "reader",
                "--roles",
                "reader",
                "--purposes",
                PURPOSE,
            ]
        )
        == 0
    )
    recalled = json.loads(capsys.readouterr().out)
    assert recalled["records"][0]["record_id"] == "cli-record"


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _control(
    cid: str = "CTRL-001",
    *,
    threshold: int = 0,
    severity: str = "HIGH",
    provenance: str = "human_confirmed",
    evidence: list[str] | None = None,
) -> dict:
    return {
        "id": cid,
        "title": "No unsafe output",
        "description": "The output must not contain the forbidden behavior.",
        "forbidden_behavior": "unsafe output reaches production",
        "gate": {
            "id": f"gate-{cid}",
            "kind": "receipt",
            "threshold": {"operator": "lte", "value": threshold},
        },
        "test": {"id": f"test-{cid}", "kind": "independent_receipt"},
        "required_evidence": evidence or ["receipt"],
        "severity": severity,
        "provenance": {
            "kind": provenance,
            "source": "human policy",
            "source_sha256": "a" * 64,
        },
        "remediation": f"Supply a fresh receipt for {cid}",
    }


def _pack(
    *,
    controls: list[dict] | None = None,
    kind: str = "human_confirmed",
    author: str = "alice",
    approver: str = "bob",
    parent: dict | None = None,
) -> dict:
    return {
        "schema": "factory.policy-pack.v1",
        "pack_id": "team-baseline",
        "version": "1.0.0",
        "provenance": {
            "kind": kind,
            "source": "reviewed baseline",
            "source_sha256": "b" * 64,
        },
        "authorship": {"author": author},
        "approval": {
            "approver": approver,
            "decision": "approved",
            "approved_at": "2026-01-01T00:00:00Z",
            "approval_sha256": "c" * 64,
        },
        "parent": parent,
        "exception_policy": {"max_ttl_days": 30},
        "controls": controls or [_control()],
    }


def _sealed_receipt(root: Path, control_id: str = "CTRL-001") -> str:
    path = root / "evidence" / f"{control_id}.json"
    payload = {
        "control_id": control_id,
        "verdict": "PASS",
        "source": "independent-run",
        "generated_at": "2026-01-01T00:00:00Z",
    }
    envelope = dict(payload)
    envelope["receipt_sha256"] = _digest(payload)
    _write(path, envelope)
    return path.as_posix()


def test_provenance_and_inheritance_are_visible(tmp_path: Path) -> None:
    parent = tmp_path / "controls" / "parent.json"
    _write(parent, _pack(controls=[_control("CTRL-PARENT")]))
    child = tmp_path / "controls" / "child.json"
    _write(
        child,
        _pack(
            controls=[_control("CTRL-CHILD")],
            parent={
                "path": "parent.json",
                "sha256": hashlib.sha256(parent.read_bytes()).hexdigest(),
            },
        ),
    )
    resolved = load_policy_pack(tmp_path, "controls/child.json")
    assert resolved["status"] == "ENFORCED"
    assert resolved["inherited_control_ids"] == ["CTRL-PARENT"]
    assert {item["id"] for item in resolved["controls"]} == {
        "CTRL-PARENT",
        "CTRL-CHILD",
    }

    nested_parent = tmp_path / "org-parent.json"
    _write(nested_parent, _pack(controls=[_control("CTRL-ORG")]))
    nested_child = tmp_path / "controls" / "nested.json"
    _write(
        nested_child,
        _pack(
            controls=[],
            parent={
                "path": "../org-parent.json",
                "sha256": hashlib.sha256(nested_parent.read_bytes()).hexdigest(),
            },
        ),
    )
    assert "CTRL-ORG" in {
        item["id"]
        for item in load_policy_pack(tmp_path, "controls/nested.json")["controls"]
    }

    proposed = tmp_path / "controls" / "proposed.json"
    _write(proposed, _pack(kind="agent_proposed", author="agent", approver="agent"))
    assert load_policy_pack(tmp_path, "controls/proposed.json")["status"] == "ADVISORY"


def test_weakening_and_deletion_fail_closed(tmp_path: Path) -> None:
    parent = tmp_path / "controls" / "parent.json"
    _write(parent, _pack(controls=[_control(threshold=0)]))
    weakened = tmp_path / "controls" / "child.json"
    child = _pack(controls=[_control(threshold=5)])
    child["parent"] = {
        "path": "parent.json",
        "sha256": hashlib.sha256(parent.read_bytes()).hexdigest(),
    }
    _write(weakened, child)
    with pytest.raises(ControlsError, match="cannot weaken") as error:
        load_policy_pack(tmp_path, "controls/child.json")
    assert error.value.code == "E_CONTROL_WEAKENING"

    deleted = tmp_path / "controls" / "deleted.json"
    deleted_value = _pack(controls=[])
    deleted_value["parent"] = {
        "path": "parent.json",
        "sha256": hashlib.sha256(parent.read_bytes()).hexdigest(),
    }
    deleted_value["remove_controls"] = ["CTRL-001"]
    _write(deleted, deleted_value)
    with pytest.raises(ControlsError) as deleted_error:
        load_policy_pack(tmp_path, "controls/deleted.json")
    assert deleted_error.value.code == "E_CONTROL_DELETED"


def test_evaluation_blocks_without_evidence_and_reports_drift(tmp_path: Path) -> None:
    policy = tmp_path / "controls" / "policy.json"
    _write(policy, _pack())
    evaluation = evaluate_controls(
        tmp_path,
        "controls/policy.json",
        baseline={"effective_sha256": "d" * 64},
        event={"kind": "deployment", "actor": "agent", "commit": "abc"},
    )
    assert evaluation["decision"] == "REVIEW_REQUIRED"
    assert evaluation["coverage"]["blocked"] == 1
    assert evaluation["drift"]["state"] == "BLOCKED"
    assert evaluation["next_action"]["control_id"] == "CTRL-001"
    assert evaluation["authority"] == {
        "release": False,
        "merge": False,
        "deploy": False,
        "credentials": False,
    }
    passed = evaluate_controls(
        tmp_path, "controls/policy.json", evidence_paths=[_sealed_receipt(tmp_path)]
    )
    assert passed["controls"][0]["status"] == "PASSED"
    assert passed["decision"] == "READY_FOR_HUMAN_REVIEW"


def test_exception_sod_ttl_and_expiry(tmp_path: Path) -> None:
    policy = tmp_path / "controls" / "policy.json"
    _write(policy, _pack())
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("approved compensating control\n", encoding="utf-8")
    exception = create_exception(
        tmp_path,
        "controls/policy.json",
        "CTRL-001",
        owner="ops",
        reason="hotfix",
        scope="release/123",
        ttl_days=7,
        evidence_path="evidence.txt",
        author="alice",
        approver="bob",
        out="controls/exception.json",
    )
    assert exception["status"] == "ACTIVE"
    assert exception["approval"]["approver"] == "bob"
    result = evaluate_controls(
        tmp_path, "controls/policy.json", exception_paths=["controls/exception.json"]
    )
    assert result["controls"][0]["status"] == "EXEMPT"
    with pytest.raises(ControlsError) as error:
        create_exception(
            tmp_path,
            "controls/policy.json",
            "CTRL-001",
            owner="ops",
            reason="bad",
            scope="all",
            ttl_days=31,
            evidence_path="evidence.txt",
            author="alice",
            approver="bob",
        )
    assert error.value.code == "E_EXCEPTION_TTL"


def test_graph_dossier_and_projection(tmp_path: Path) -> None:
    policy = tmp_path / "controls" / "policy.json"
    _write(policy, _pack())
    evaluation = evaluate_controls(tmp_path, "controls/policy.json")
    stored = write_control_evaluation(tmp_path, evaluation)
    graph = build_control_graph(evaluation)
    relations = [edge["relation"] for edge in graph["edges"]]
    assert relations[:6] == [
        "defines",
        "forbids",
        "guards",
        "challenged_by",
        "evidenced_by",
        "decides",
    ]
    assert graph["graph_sha256"]
    assert "One next action" in render_controls_review(evaluation)
    dossier = write_controls_dossier(tmp_path, evaluation)
    assert Path(tmp_path / dossier["json"]).is_file()
    projection = continuous_controls_projection(tmp_path)
    assert projection["evaluation_count"] == 1
    assert verify_control_evaluation(tmp_path, stored["path"])["verified"]


def test_fleet_coverage(tmp_path: Path) -> None:
    for name in ("one", "two"):
        repo = tmp_path / "repos" / name
        _write(
            repo / "controls" / "policy.json",
            _pack(controls=[_control("CTRL-001" if name == "one" else "CTRL-002")]),
        )
    fleet = {
        "schema": "factory.control-fleet.v1",
        "baseline_controls": ["CTRL-001", "CTRL-002"],
        "repositories": [
            {"id": "one", "path": "repos/one", "policy": "controls/policy.json"},
            {"id": "two", "path": "repos/two", "policy": "controls/policy.json"},
        ],
    }
    _write(tmp_path / "controls" / "fleet.json", fleet)
    result = fleet_coverage(tmp_path)
    assert result["repositories"][0]["missing_baseline"]
    assert result["repositories"][1]["missing_baseline"]


def _operator(tenant: str = "tenant-a", subject: str = "operator") -> Principal:
    return Principal(subject=subject, tenant_id=tenant, roles=("operator",))


def _approver(tenant: str = "tenant-a", subject: str = "approver") -> Principal:
    return Principal(subject=subject, tenant_id=tenant, roles=("approver",))


def _admin(tenant: str = "tenant-a", subject: str = "admin") -> Principal:
    return Principal(subject=subject, tenant_id=tenant, roles=("admin",))


def _evidence(tenant: str = "tenant-a") -> dict:
    return {
        "schema": "factory.receipt.v2",
        "tenant_id": tenant,
        "subject_digest": "a" * 64,
        "policy_sha256": "b" * 64,
        "verdict": "VERIFIED",
        "stage": "compile",
    }


def test_contract_document_is_present():
    path = Path("specs/control-plane.md")
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "tenant boundary" in text
    assert "hash-link" in text


def test_tenant_scoped_evidence_round_trip(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    record = store.put(_operator(), _evidence(), evidence_id="e-1")
    assert record["evidence_id"] == "e-1"
    assert record["payload_sha256"]
    assert store.get(_operator(), "tenant-a", "e-1")["payload"]["verdict"] == "VERIFIED"
    assert len(store.list(_operator(), "tenant-a")) == 1
    assert store.verify_audit(_operator(), "tenant-a")["valid"] is True


def test_cross_tenant_read_and_write_are_denied_before_access(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    store.put(_operator(), _evidence(), evidence_id="e-1")
    with pytest.raises(ControlPlaneError, match="another tenant") as read_error:
        store.get(_operator(), "tenant-b", "e-1")
    assert read_error.value.code == "E_TENANT_BOUNDARY"
    with pytest.raises(ControlPlaneError) as write_error:
        store.put(_operator(), _evidence("tenant-b"), evidence_id="e-2")
    assert write_error.value.code == "E_TENANT_BOUNDARY"
    assert store.list(_operator(), "tenant-a")[0]["evidence_id"] == "e-1"


def test_unknown_role_is_denied(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    with pytest.raises(ControlPlaneError) as error:
        store.put(Principal("guest", "tenant-a", ("unknown",)), _evidence())
    assert error.value.code == "E_ACTION_DENIED"


def test_repair_execute_grant_is_limited_to_operator_and_admin():
    authorize(_operator(), "repair.execute", "tenant-a")
    authorize(_admin(), "repair.execute", "tenant-a")
    for principal in (
        Principal("reader", "tenant-a", ("viewer",)),
        Principal("approver", "tenant-a", ("approver",)),
        Principal("platform", "*", ("platform_admin",)),
    ):
        with pytest.raises(ControlPlaneError) as error:
            authorize(principal, "repair.execute", "tenant-a")
        assert error.value.code == "E_ACTION_DENIED"


def test_approval_requires_distinct_approver_and_records_reason(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    request = store.request_approval(
        _admin(),
        "tenant-a",
        store.put(_admin(), _evidence())["evidence_id"],
        "release candidate",
    )
    with pytest.raises(ControlPlaneError) as self_error:
        store.decide_approval(
            _admin(), "tenant-a", request["approval_id"], "approved", "I approve"
        )
    assert self_error.value.code == "E_SELF_APPROVAL"
    decided = store.decide_approval(
        _approver(),
        "tenant-a",
        request["approval_id"],
        "approved",
        "independent review complete",
    )
    assert decided["status"] == "approved"
    assert decided["approver"] == "approver"
    assert decided["decision_reason"] == "independent review complete"
    with pytest.raises(ControlPlaneError) as second_error:
        store.decide_approval(
            _approver("tenant-a", "second-approver"),
            "tenant-a",
            request["approval_id"],
            "rejected",
            "too late",
        )
    assert second_error.value.code == "E_ALREADY_DECIDED"


def test_cross_tenant_approval_is_denied(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    evidence_id = store.put(_operator(), _evidence())["evidence_id"]
    request = store.request_approval(_operator(), "tenant-a", evidence_id, "review")
    with pytest.raises(ControlPlaneError) as error:
        store.decide_approval(
            _approver("tenant-b", "other"),
            "tenant-a",
            request["approval_id"],
            "approved",
            "bad",
        )
    assert error.value.code == "E_TENANT_BOUNDARY"


def test_audit_tampering_is_detected_without_cross_tenant_leak(tmp_path):
    db_path = tmp_path / "evidence.sqlite3"
    store = EvidenceStore(db_path)
    store.put(_operator(), _evidence(), evidence_id="e-1")
    store.put(_operator("tenant-b", "other"), _evidence("tenant-b"), evidence_id="e-2")
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE audit_events SET payload_json = ? WHERE tenant_id = ?",
            (json.dumps({"changed": True}), "tenant-a"),
        )
        db.commit()
    result = store.verify_audit(_operator(), "tenant-a")
    assert result["valid"] is False
    assert result["events"] == 1
    assert all("tenant-b" not in error for error in result["errors"])


def test_cli_control_plane_round_trip(tmp_path, capsys):
    db = tmp_path / "control.sqlite3"
    payload = tmp_path / "receipt.json"
    payload.write_text(json.dumps(_evidence()), encoding="utf-8")
    assert main(["control", "init", "--db", str(db)]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "control",
                "evidence-put",
                str(payload),
                "--db",
                str(db),
                "--tenant",
                "tenant-a",
                "--subject",
                "ci",
                "--roles",
                "operator",
            ]
        )
        == 0
    )
    evidence = json.loads(capsys.readouterr().out)
    assert evidence["tenant_id"] == "tenant-a"
    assert (
        main(
            [
                "control",
                "audit-verify",
                "--db",
                str(db),
                "--tenant",
                "tenant-a",
                "--subject",
                "audit",
                "--roles",
                "viewer",
            ]
        )
        == 0
    )
    audit = json.loads(capsys.readouterr().out)
    assert audit["valid"] is True


def _api_call(app, method, path, *, body=None, subject=None, tenant=None, roles=None):
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    data = json.dumps(body).encode("utf-8") if body is not None else b""
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(data)),
        "wsgi.input": BytesIO(data),
    }
    if subject is not None:
        environ["HTTP_X_FACTORY_SUBJECT"] = subject
    if tenant is not None:
        environ["HTTP_X_FACTORY_TENANT"] = tenant
    if roles is not None:
        environ["HTTP_X_FACTORY_ROLES"] = roles
    result = b"".join(app(environ, start_response))
    return captured["status"], json.loads(result)


def test_rest_adapter_requires_identity_and_supports_approval_flow(tmp_path):
    app = ControlPlaneAPI(tmp_path / "api.sqlite3")
    status, health = _api_call(app, "GET", "/healthz")
    assert status == "200 OK" and health["ok"] is True
    status, denied = _api_call(app, "GET", "/v1/evidence")
    assert status == "400 Bad Request"
    assert denied["error"]["code"] == "E_IDENTITY_REQUIRED"
    status, evidence = _api_call(
        app,
        "POST",
        "/v1/evidence",
        body=_evidence(),
        subject="ci",
        tenant="tenant-a",
        roles="operator",
    )
    assert status == "201 Created"
    evidence_id = evidence["evidence_id"]
    status, request = _api_call(
        app,
        "POST",
        f"/v1/evidence/approvals/{evidence_id}",
        body={"reason": "release review"},
        subject="ci",
        tenant="tenant-a",
        roles="operator",
    )
    assert status == "201 Created"
    status, decided = _api_call(
        app,
        "POST",
        f"/v1/evidence/approvals/{request['approval_id']}/decision",
        body={"decision": "approved", "reason": "independent review"},
        subject="release-manager",
        tenant="tenant-a",
        roles="approver",
    )
    assert status == "200 OK" and decided["status"] == "approved"
    status, audit = _api_call(
        app, "GET", "/v1/audit", subject="audit", tenant="tenant-a", roles="viewer"
    )
    assert status == "200 OK" and audit["valid"] is True


def workflow_approval_setup(
    tmp_path, *, decision="approved", expires_at="2099-01-01T00:00:00+00:00"
):
    expected = dict(
        source_sha256="a" * 64,
        run_id="run-1",
        phase="planning",
        kind="approved_plan",
        artifact_sha256="b" * 64,
        verifier_id="approval-host",
    )
    store = EvidenceStore(tmp_path / "approvals.sqlite3")
    record = store.put(
        _operator(),
        dict(
            schema="factory.workflow-approval.v1",
            tenant_id="tenant-a",
            expires_at=expires_at,
            phase_evidence=expected,
        ),
    )
    approval = store.request_approval(
        _operator(), "tenant-a", record["evidence_id"], "Review bound plan"
    )
    if decision != "pending":
        store.decide_approval(
            _approver(),
            "tenant-a",
            approval["approval_id"],
            decision,
            "Independent review",
        )
    return store, approval["approval_id"], expected


def test_workflow_approval_verifier_survives_restart_and_exact_retry(tmp_path):
    store, approval_id, expected = workflow_approval_setup(tmp_path)

    def resolver(subject, tenant):
        return _approver(tenant, subject)

    verifier = EvidenceStore(store.path).workflow_approval_verifier(
        _operator(), "tenant-a", approval_id, resolve_principal=resolver
    )
    assert verifier(expected) == expected
    assert verifier(expected) == expected
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute("SELECT count(*) FROM workflow_approval_uses").fetchone()[0] == 1
        )
        assert (
            db.execute(
                "SELECT count(*) FROM audit_events WHERE action='approval.workflow.consume'"
            ).fetchone()[0]
            == 1
        )
    assert store.verify_audit(_operator(), "tenant-a")["valid"]


def test_workflow_repair_dispatch_requires_authenticated_requester(tmp_path):
    store, approval_id, expected = workflow_approval_setup(tmp_path)
    other = Principal("other-operator", "tenant-a", ("operator",))
    verifier = store.workflow_approval_verifier(
        other,
        "tenant-a",
        approval_id,
        resolve_principal=lambda subject, tenant: _approver(tenant, subject),
        require_requester=True,
    )
    with pytest.raises(ControlPlaneError) as error:
        verifier(expected)
    assert error.value.code == "E_APPROVAL_REQUESTER"


@pytest.mark.parametrize("decision", ["pending", "rejected"])
def test_workflow_approval_requires_approved_decision(tmp_path, decision):
    store, approval_id, expected = workflow_approval_setup(tmp_path, decision=decision)
    verifier = store.workflow_approval_verifier(
        _operator(),
        "tenant-a",
        approval_id,
        resolve_principal=lambda s, t: _approver(t, s),
    )
    with pytest.raises(ControlPlaneError) as caught:
        verifier(expected)
    assert caught.value.code == "E_APPROVAL_REQUIRED"


@pytest.mark.parametrize(
    "expiry", ["2000-01-01T00:00:00+00:00", "2099-01-01", "invalid"]
)
def test_workflow_approval_rejects_expired_or_invalid_expiry(tmp_path, expiry):
    store, approval_id, expected = workflow_approval_setup(tmp_path, expires_at=expiry)
    verifier = store.workflow_approval_verifier(
        _operator(),
        "tenant-a",
        approval_id,
        resolve_principal=lambda s, t: _approver(t, s),
    )
    with pytest.raises(ControlPlaneError) as caught:
        verifier(expected)
    assert caught.value.code == "E_APPROVAL_EVIDENCE"


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_sha256", "c" * 64),
        ("run_id", "other-run"),
        ("artifact_sha256", "d" * 64),
        ("phase", "building"),
    ],
)
def test_workflow_approval_rejects_different_binding(tmp_path, field, value):
    store, approval_id, expected = workflow_approval_setup(tmp_path)
    verifier = store.workflow_approval_verifier(
        _operator(),
        "tenant-a",
        approval_id,
        resolve_principal=lambda s, t: _approver(t, s),
    )
    with pytest.raises(ControlPlaneError):
        verifier({**expected, field: value})
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute("SELECT count(*) FROM workflow_approval_uses").fetchone()[0] == 0
        )


@pytest.mark.parametrize(
    "resolver",
    [
        lambda s, t: _operator(t, s),
        lambda s, t: _approver(t, "imposter"),
        lambda s, t: _approver("tenant-b", s),
        lambda s, t: None,
    ],
)
def test_workflow_approval_rechecks_current_identity_and_role(tmp_path, resolver):
    store, approval_id, expected = workflow_approval_setup(tmp_path)
    verifier = store.workflow_approval_verifier(
        _operator(), "tenant-a", approval_id, resolve_principal=resolver
    )
    with pytest.raises(ControlPlaneError):
        verifier(expected)


def test_workflow_approval_rejects_cross_tenant_and_missing_resolver(tmp_path):
    store, approval_id, expected = workflow_approval_setup(tmp_path)
    with pytest.raises(ControlPlaneError):
        store.workflow_approval_verifier(
            _operator(),
            "tenant-b",
            approval_id,
            resolve_principal=lambda s, t: _approver(t, s),
        )
    with pytest.raises(ControlPlaneError):
        store.workflow_approval_verifier(
            _operator(), "tenant-a", approval_id, resolve_principal=None
        )


def test_workflow_approval_corrupt_evidence_is_not_consumed(tmp_path):
    store, approval_id, expected = workflow_approval_setup(tmp_path)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE evidence SET payload_json='null'")
    verifier = store.workflow_approval_verifier(
        _operator(),
        "tenant-a",
        approval_id,
        resolve_principal=lambda s, t: _approver(t, s),
    )
    with pytest.raises(ControlPlaneError) as caught:
        verifier(expected)
    assert caught.value.code == "E_APPROVAL_EVIDENCE"


def test_workflow_approval_concurrent_retry_records_one_consumption(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    store, approval_id, expected = workflow_approval_setup(tmp_path)

    def consume():
        reopened = EvidenceStore(store.path)
        verify = reopened.workflow_approval_verifier(
            _operator(),
            "tenant-a",
            approval_id,
            resolve_principal=lambda s, t: _approver(t, s),
        )
        return verify(expected)

    with ThreadPoolExecutor(max_workers=2) as workers:
        assert list(workers.map(lambda _: consume(), range(2))) == [expected, expected]
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute("SELECT count(*) FROM workflow_approval_uses").fetchone()[0] == 1
        )
        assert (
            db.execute(
                "SELECT count(*) FROM audit_events WHERE action='approval.workflow.consume'"
            ).fetchone()[0]
            == 1
        )


def test_workflow_approval_failed_audit_rolls_back_consumption(tmp_path, monkeypatch):
    store, approval_id, expected = workflow_approval_setup(tmp_path)
    original = store._audit

    def fail(*args, **kwargs):
        raise RuntimeError("interruption")

    monkeypatch.setattr(store, "_audit", fail)
    verify = store.workflow_approval_verifier(
        _operator(),
        "tenant-a",
        approval_id,
        resolve_principal=lambda s, t: _approver(t, s),
    )
    with pytest.raises(RuntimeError, match="interruption"):
        verify(expected)
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute("SELECT count(*) FROM workflow_approval_uses").fetchone()[0] == 0
        )
    monkeypatch.setattr(store, "_audit", original)
    assert verify(expected) == expected


def test_workflow_approval_rejects_reused_fingerprint_and_revoked_role(tmp_path):
    store, approval_id, expected = workflow_approval_setup(tmp_path)
    verify = store.workflow_approval_verifier(
        _operator(),
        "tenant-a",
        approval_id,
        resolve_principal=lambda s, t: _approver(t, s),
    )
    assert verify(expected) == expected
    revoked = store.workflow_approval_verifier(
        _operator(),
        "tenant-a",
        approval_id,
        resolve_principal=lambda s, t: _operator(t, s),
    )
    with pytest.raises(ControlPlaneError) as caught:
        revoked(expected)
    assert caught.value.code == "E_ACTION_DENIED"
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE workflow_approval_uses SET fingerprint=?", ("c" * 64,))
    with pytest.raises(ControlPlaneError) as caught:
        verify(expected)
    assert caught.value.code == "E_APPROVAL_REPLAY"


def test_workflow_approval_changed_during_identity_resolution_is_fenced(tmp_path):
    store, approval_id, expected = workflow_approval_setup(tmp_path)

    def resolve(subject, tenant):
        with sqlite3.connect(store.path) as db:
            db.execute(
                "UPDATE approvals SET status='rejected' WHERE approval_id=?",
                (approval_id,),
            )
        return _approver(tenant, subject)

    verify = store.workflow_approval_verifier(
        _operator(), "tenant-a", approval_id, resolve_principal=resolve
    )
    with pytest.raises(ControlPlaneError) as caught:
        verify(expected)
    assert caught.value.code == "E_APPROVAL_CHANGED"
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute("SELECT count(*) FROM workflow_approval_uses").fetchone()[0] == 0
        )


def test_live_activity_projects_current_stage_and_cooperative_stop(tmp_path):
    activity = LiveActivity(tmp_path, "run-123", "proof-review", 3)
    activity.start()
    activity.stage_started("forgeline", "verify-tests")

    current = activity_snapshot(tmp_path)
    assert current["available"] is True
    assert current["status"] == "active"
    assert current["current_stage"] == {
        "module": "forgeline",
        "stage": "verify-tests",
        "started_at": current["current_stage"]["started_at"],
    }
    assert current["elapsed_ms"] is not None

    result = request_stop(tmp_path)
    assert result["marker"] == "LIVE_ACTIVITY_STOP_REQUESTED"
    assert activity.heartbeat() is False

    activity.finish("halted", halted_at="forgeline:verify-tests")
    completed = activity_snapshot(tmp_path)
    assert completed["status"] == "halted"
    assert completed["halted_at"] == "forgeline:verify-tests"


def test_live_activity_marks_missing_heartbeats_stale_without_rewriting_receipt_state(
    tmp_path,
):
    activity = LiveActivity(tmp_path, "run-456", "sample", 1)
    activity.start()

    stale = activity_snapshot(tmp_path, stale_after_seconds=-1)
    assert stale["status"] == "stale"
    assert "LIVE_ACTIVITY_STALE" in stale["markers"]


PRD = """# Graph Runtime Fixture

## Actors
- Maintainer: owns the migration contract.

## Outcomes
- Preserve deterministic package behavior.

## Requirements
- REQ-COMPILE: The compiler must preserve deterministic package behavior.

## Acceptance
Scenario: Compile the migrated package
  Given a clean source tree
  When the package is compiled twice
  Then both artifact hashes are identical
"""


def _pipeline(tmp_path: Path, **budgets):
    tmp_path.mkdir(parents=True, exist_ok=True)
    prd = tmp_path / "PRD.md"
    prd.write_text(PRD, encoding="utf-8")
    graph = compile_product_prd(prd, tmp_path)
    slices = plan_value_slices(Path(graph["path"]), tmp_path)
    return create_mission(
        Path(slices["path"]),
        slices["slices"][0]["id"],
        tmp_path,
        "mission-owner",
        **budgets,
    )


def _receipt(tmp_path: Path, name: str, schema: str, mission_id: str, **values) -> Path:
    path = tmp_path / name
    path.write_text(
        json.dumps({"schema": schema, "mission_id": mission_id, **values}),
        encoding="utf-8",
    )
    return path


def _candidate_with_evidence(
    tmp_path: Path, name: str, mission: dict, diff_sha256: str, evidence_name: str
) -> Path:
    evidence = tmp_path / evidence_name
    evidence.write_text(f"evidence for {name}\n", encoding="utf-8")
    return _receipt(
        tmp_path,
        name,
        "factory.mission.candidate.v1",
        mission["id"],
        candidate={"diff_sha256": diff_sha256, "changed_paths": ["src/example.py"]},
        evidence=[
            {
                "path": evidence.name,
                "sha256": sha256(evidence.read_bytes()).hexdigest(),
                "kind": "test_result",
            }
        ],
    )


def _completion(tmp_path: Path, mission: dict, creator: str, verifier: str) -> Path:
    evidence = tmp_path / f"evidence-{creator}.json"
    evidence.write_text('{"passed":true}\n', encoding="utf-8")
    validation = tmp_path / f"validation-{creator}.json"
    validation.write_text(
        json.dumps(
            {
                "schema": "factory.mission.validation-input.v1",
                "creator_id": creator,
                "verifier_id": verifier,
                "verifier_context": [
                    "mission.json",
                    "candidate_diff",
                    "evidence_manifest",
                ],
                "adapter_attestation": {
                    "schema": "factory.verifier-attestation.v1",
                    "mission_digest": mission["mission_sha256"],
                    "contract_digest": "c" * 64,
                    "creator_id": creator,
                    "verifier_id": verifier,
                    "verifier_context": [
                        "mission.json",
                        "candidate_diff",
                        "evidence_manifest",
                    ],
                    "fresh_session": True,
                    "context_wall": "isolated",
                    "evidence_digest": "d" * 64,
                    "adapter_id": "test-adapter",
                },
                "criteria": [
                    {"id": item["id"], "passed": True, "evidence": [str(evidence)]}
                    for item in mission["completion_contract"]["criteria"]
                ],
            }
        ),
        encoding="utf-8",
    )
    return Path(close_mission(Path(mission["path"]), validation, tmp_path)["path"])


def test_mission_graph_history_returns_bound_ordered_events(tmp_path: Path):
    mission = _pipeline(tmp_path)
    initialized = init_mission_graph(Path(mission["path"]), tmp_path)

    history = mission_graph_history(Path(mission["path"]), tmp_path)

    assert history["schema"] == "factory.mission.graph.history.v1"
    assert history["mission_id"] == mission["id"]
    assert history["state"] == initialized["state"] == "planned"
    assert history["version"] == initialized["version"] == 0
    assert history["events"] == []
    assert history["chain_head"] == initialized["event_tip"]
    assert history["marker"] == "MISSION_GRAPH_HASH_CHAIN_BOUND"


def _approve(tmp_path: Path, mission: dict) -> Path:
    return Path(
        decide_mission(
            Path(mission["path"]),
            tmp_path,
            owner="mission-owner",
            decision="approved_execution",
            rationale="The bounded plan is ready.",
        )["path"]
    )


def test_native_graph_rejects_legacy_claim_as_daily_completion(tmp_path: Path):
    import pytest
    from factoryline.mission_graph import MissionGraphError

    mission = _pipeline(tmp_path)
    initialized = init_mission_graph(Path(mission["path"]), tmp_path)
    assert initialized["state"] == "planned"
    assert initialized["marker"] == "MISSION_GRAPH_INITIALIZED"
    assert initialized["milestone_progress"]["total"] == len(
        mission["completion_contract"]["criteria"]
    )

    approved = apply_mission_event(
        Path(mission["path"]),
        tmp_path,
        "approve",
        "mission-owner",
        "owner",
        "approve-1",
        _approve(tmp_path, mission),
    )
    assert approved["state"] == "creator_running"
    candidate_1 = _candidate_with_evidence(
        tmp_path, "candidate-1.json", mission, "a" * 64, "candidate-1-evidence.txt"
    )
    apply_mission_event(
        Path(mission["path"]),
        tmp_path,
        "candidate_ready",
        "worker-1",
        "worker",
        "candidate-1",
        candidate_1,
    )
    failed = _receipt(
        tmp_path, "failed.json", "factory.mission.validation-failure.v1", mission["id"]
    )
    criterion_id = mission["completion_contract"]["criteria"][0]["id"]
    result = apply_mission_event(
        Path(mission["path"]),
        tmp_path,
        "validation_failed",
        "verifier-1",
        "validator",
        "failed-1",
        failed,
        {"criterion_id": criterion_id},
    )
    assert result["state"] == "correction_required"
    candidate_2 = _candidate_with_evidence(
        tmp_path, "candidate-2.json", mission, "b" * 64, "candidate-2-evidence.txt"
    )
    retry = tmp_path / ".factory" / "proof-deltas" / "retry.json"
    create_proof_delta(
        tmp_path,
        Path(mission["path"]),
        candidate_1,
        candidate_2,
        failed,
        criterion_id,
        retry,
    )
    result = apply_mission_event(
        Path(mission["path"]),
        tmp_path,
        "retry",
        "mission-owner",
        "owner",
        "retry-1",
        retry,
        {"fresh_context": True},
    )
    assert result["state"] == "creator_running"
    assert result["attempts"] == 2
    apply_mission_event(
        Path(mission["path"]),
        tmp_path,
        "candidate_ready",
        "worker-2",
        "worker",
        "candidate-2",
        candidate_2,
    )
    completion = _completion(tmp_path, mission, "worker-2", "verifier-2")
    with pytest.raises(MissionGraphError, match="integrity-valid but incomplete"):
        apply_mission_event(
            Path(mission["path"]),
            tmp_path,
            "validation_passed",
            "verifier-2",
            "validator",
            "passed-2",
            completion,
        )
    assert mission_graph_status(Path(mission["path"]), tmp_path)["state"] == (
        "independent_verification"
    )


def test_completion_gate_accepts_upstream_verified_complete_receipt(
    tmp_path, monkeypatch
):
    import factoryline.mission_graph as mission_graph

    mission = {"mission_sha256": "a" * 64}
    receipt = {
        "mission": {"mission_sha256": mission["mission_sha256"]},
        "verifier_id": "reviewer",
        "creator_id": "builder",
    }
    monkeypatch.setattr(
        mission_graph,
        "verify_mission_completion",
        lambda _path: {"valid": True, "complete": True, "errors": []},
    )
    mission_graph._completion_receipt(
        tmp_path / "completion.json", receipt, mission, "reviewer", "builder"
    )


def test_native_graph_rejects_replay_role_confusion_and_receipt_drift(tmp_path: Path):
    mission = _pipeline(tmp_path)
    decision = _approve(tmp_path, mission)
    first = apply_mission_event(
        Path(mission["path"]),
        tmp_path,
        "approve",
        "mission-owner",
        "owner",
        "same-key",
        decision,
    )
    duplicate = apply_mission_event(
        Path(mission["path"]),
        tmp_path,
        "approve",
        "mission-owner",
        "owner",
        "same-key",
        decision,
    )
    assert duplicate["marker"] == "MISSION_GRAPH_IDEMPOTENT"
    assert duplicate["version"] == first["version"]
    candidate = _receipt(
        tmp_path, "candidate.json", "factory.mission.candidate.v1", mission["id"]
    )
    with pytest.raises(MissionGraphError, match="MISSION_GRAPH_IDEMPOTENCY_CONFLICT"):
        apply_mission_event(
            Path(mission["path"]),
            tmp_path,
            "candidate_ready",
            "worker",
            "worker",
            "same-key",
            candidate,
        )
    apply_mission_event(
        Path(mission["path"]),
        tmp_path,
        "candidate_ready",
        "worker",
        "worker",
        "candidate",
        candidate,
    )
    failure = _receipt(
        tmp_path, "failure.json", "factory.mission.validation-failure.v1", mission["id"]
    )
    with pytest.raises(MissionGraphError, match="MISSION_GRAPH_VERIFIER_NOT_DISTINCT"):
        apply_mission_event(
            Path(mission["path"]),
            tmp_path,
            "validation_failed",
            "worker",
            "validator",
            "self-verify",
            failure,
            {"criterion_id": mission["completion_contract"]["criteria"][0]["id"]},
        )
    candidate.write_text(
        '{"schema":"factory.mission.candidate.v1","mission_id":"tampered"}',
        encoding="utf-8",
    )
    assert (
        verify_mission_graph(Path(mission["path"]), tmp_path)["marker"]
        == "MISSION_GRAPH_DRIFT"
    )


def test_native_budget_kill_switch_and_route_are_measured(tmp_path: Path):
    mission = _pipeline(tmp_path, max_cost_usd=1.0)
    apply_mission_event(
        Path(mission["path"]),
        tmp_path,
        "approve",
        "mission-owner",
        "owner",
        "approve",
        _approve(tmp_path, mission),
    )
    usage = _receipt(
        tmp_path,
        "usage.json",
        "factory.mission.usage.v1",
        mission["id"],
        evidence_class="measured",
        tokens=None,
        cost_usd=1.0,
        wall_seconds=2.0,
    )
    result = apply_mission_event(
        Path(mission["path"]),
        tmp_path,
        "usage_recorded",
        "worker",
        "worker",
        "usage",
        usage,
    )
    assert result["state"] == "budget_exhausted"
    assert result["marker"] == "MISSION_GRAPH_BUDGET_ENFORCED"
    candidate = _receipt(
        tmp_path, "candidate.json", "factory.mission.candidate.v1", mission["id"]
    )
    with pytest.raises(MissionGraphError, match="MISSION_GRAPH_TRANSITION_INVALID"):
        apply_mission_event(
            Path(mission["path"]),
            tmp_path,
            "candidate_ready",
            "worker",
            "worker",
            "candidate",
            candidate,
        )

    fresh = _pipeline(tmp_path / "route")
    route = recommend_mission_route(Path(fresh["path"]), tmp_path / "route", "high")
    assert route["tier"] == "frontier"
    assert route["provider_or_model"] is None
    assert route["marker"] == "MISSION_GRAPH_ROUTING_EXPLAINED"


def test_native_owner_can_pause_bind_a_plan_and_resume_fresh(tmp_path: Path):
    mission = _pipeline(tmp_path)
    apply_mission_event(
        Path(mission["path"]),
        tmp_path,
        "approve",
        "mission-owner",
        "owner",
        "approve",
        _approve(tmp_path, mission),
    )
    pause = _receipt(
        tmp_path, "pause.json", "factory.mission.human-interrupt.v1", mission["id"]
    )
    result = apply_mission_event(
        Path(mission["path"]),
        tmp_path,
        "pause",
        "mission-owner",
        "owner",
        "pause",
        pause,
    )
    assert result["state"] == "paused_for_review"
    plan = _receipt(
        tmp_path, "plan.json", "factory.mission.plan-revision.v1", mission["id"]
    )
    apply_mission_event(
        Path(mission["path"]),
        tmp_path,
        "plan_revised",
        "mission-owner",
        "owner",
        "plan",
        plan,
    )
    result = apply_mission_event(
        Path(mission["path"]),
        tmp_path,
        "resume",
        "mission-owner",
        "owner",
        "resume",
        plan,
        {"fresh_context": True},
    )
    assert result["state"] == "creator_running"
    assert result["creator_id"] is None
    assert result["plan_receipt"]["sha256"]
    exported = export_mission_graph(Path(mission["path"]), tmp_path)
    assert exported["marker"] == "MISSION_GRAPH_MERMAID_EXPORTED"
    assert Path(exported["path"]).is_file()


def test_langgraph_adapter_checkpoints_native_transition(tmp_path: Path):
    mission = _pipeline(tmp_path)
    doctor = langgraph_doctor()
    if not doctor["ready"]:
        pytest.skip("requires both langgraph and langgraph-checkpoint-sqlite")
    graph = build_langgraph_adapter(Path(mission["path"]), tmp_path)
    config = {"configurable": {"thread_id": mission["id"]}}
    result = graph.invoke(
        {
            "event": "approve",
            "actor": "mission-owner",
            "role": "owner",
            "idempotency_key": "langgraph-approve",
            "receipt_path": str(_approve(tmp_path, mission)),
            "payload": {},
        },
        config=config,
    )
    assert result["result"]["state"] == "creator_running"
    assert result["result"]["adapter_marker"] == "LANGGRAPH_ADAPTER_BOUND"
    assert graph.get_state(config).values["result"]["version"] == 1
    assert mission_graph_status(Path(mission["path"]), tmp_path)["version"] == 1


def _calibration_bundle(
    root: Path,
    *,
    case_labels: list[list[str]],
    predicted_labels: list[list[str]],
    annotations: list[list[list[str]]] | None = None,
    assignments: list[str] | None = None,
    predicted_at: str = "2026-10-11T00:00:00+00:00",
    abstain_predictions: bool = False,
) -> tuple[dict, dict[str, Path]]:
    source_dir = root / "src"
    source_dir.mkdir()
    source = source_dir / "sample.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    for args in (
        ["init", "--quiet"],
        ["config", "user.name", "Calibration Test"],
        ["config", "user.email", "calibration@example.invalid"],
        ["add", "src/sample.py"],
        ["commit", "--quiet", "-m", "fixture"],
    ):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    trace = build_audit_trace(
        root,
        changed_paths=["src/sample.py"],
        lane_states={"tests": "PASS"},
        steps=[
            {
                "step_id": "bound-source",
                "input": "sha256:" + hashlib.sha256(b"input").hexdigest(),
                "guard": "SOURCE_BOUND",
                "decision": "RECORD",
                "state": "PASS",
                "source_paths": ["src/sample.py"],
            }
        ],
    )
    bodies: dict[str, dict] = {
        "tool": {"version": "1"},
        "model": {"id": "review-model", "version": "1"},
        "prompt": {"version": "1", "template": "review"},
        "rubric": {"version": "1"},
        "policy": {"version": "1"},
    }
    identity_hashes = {
        role: hashlib.sha256(json.dumps(bodies[role]).encode("utf-8")).hexdigest()
        for role in ("model", "prompt", "rubric")
    }
    cases = []
    for index, _ in enumerate(case_labels):
        cases.append(
            {
                "case_id": f"case-{index}",
                "buggy_source": f"BUGGY_{index} = {index}\n",
                "fixed_source": f"FIXED_{index} = {index}\n",
                "judge_input": f"Review code sample {index}.",
            }
        )
    bodies["dataset"] = {
        "schema": "factory.judge-calibration.dataset.v1",
        "categories": ["risk"],
        "cases": cases,
    }
    split_names = assignments or ["holdout"] * len(cases)
    bodies["assignments"] = {
        "schema": "factory.judge-calibration.assignments.v1",
        "frozen_at": "2026-10-10T00:00:00+00:00",
        "splits": {f"case-{index}": split for index, split in enumerate(split_names)},
    }
    annotation_values = annotations or [[labels, labels] for labels in case_labels]
    annotation_rows = []
    for index, pair in enumerate(annotation_values):
        for annotator_id, labels in zip(("independent-a", "independent-b"), pair):
            annotation_rows.append(
                {
                    "case_id": f"case-{index}",
                    "annotator_id": annotator_id,
                    "labels": labels,
                    "abstained": False,
                }
            )
    bodies["annotations"] = {
        "schema": "factory.judge-calibration.annotations.v1",
        "annotators": ["independent-a", "independent-b"],
        "rows": annotation_rows,
    }
    judgments = []
    for index, labels in enumerate(predicted_labels):
        input_digest = hashlib.sha256(
            canonical_json(cases[index]["judge_input"])
        ).hexdigest()
        judgments.append(
            {
                "case_id": f"case-{index}",
                "predicted_at": predicted_at,
                "labels": [] if abstain_predictions else labels,
                "abstained": abstain_predictions,
                "input_sha256": input_digest,
                **{
                    f"{role}_sha256": digest for role, digest in identity_hashes.items()
                },
            }
        )
    bodies["judgments"] = {
        "schema": "factory.judge-calibration.judgments.v1",
        "rows": judgments,
    }
    bodies["adjudications"] = {
        "schema": "factory.judge-calibration.adjudications.v1",
        "rows": [
            {
                "case_id": f"case-{index}",
                "labels": labels,
                "abstained": False,
            }
            for index, labels in enumerate(case_labels)
        ],
    }
    paths = {"trace": root / "trace.json", "candidate": root / "candidate.json"}
    paths["trace"].write_text(json.dumps(trace), encoding="utf-8")
    paths["candidate"].write_text(json.dumps(trace["candidate"]), encoding="utf-8")
    artifact_paths: dict[str, Path] = {}
    artifact_descriptors = {}
    for role, body in bodies.items():
        path = root / f"{role}.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        artifact_paths[role] = path
        artifact_descriptors[role] = {
            "path": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    binding = {
        "schema": "factory.span-evaluation.binding-request.v1",
        "trace": {
            "path": paths["trace"].name,
            "sha256": hashlib.sha256(paths["trace"].read_bytes()).hexdigest(),
        },
        "candidate": {
            "path": paths["candidate"].name,
            "sha256": hashlib.sha256(paths["candidate"].read_bytes()).hexdigest(),
        },
        "sources": [
            {
                "path": "src/sample.py",
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            }
        ],
        "artifacts": artifact_descriptors,
        "applicability": {"model": "applicable"},
    }
    return binding, artifact_paths


def test_canary_promotes_only_after_policy_thresholds():
    good = evaluate_canary(
        artifact_digest="sha-good",
        environment="prod",
        metrics={"requests": 100, "error_rate": 0.0, "latency_p95_ms": 10},
    )
    assert good["decision"] == "PROMOTE"
    bad = evaluate_canary(
        artifact_digest="sha-bad",
        environment="prod",
        metrics={"requests": 100, "error_rate": 0.2, "latency_p95_ms": 10},
        previous_digest="sha-good",
        policy=CanaryPolicy(max_error_rate=0.01),
    )
    assert bad["decision"] == "ROLLBACK"
    receipt = rollback_receipt(
        bad, actor="release-manager", reason="error budget exceeded"
    )
    assert receipt["to_digest"] == "sha-good"


def test_telemetry_is_measured_and_errors_are_recorded():
    recorder = TelemetryRecorder("acme")
    with measured_span(recorder, "compile"):
        time.sleep(0.001)
    assert recorder.spans[0]["duration_ms"] >= 0
    with pytest.raises(RuntimeError):
        with measured_span(recorder, "failed"):
            raise RuntimeError("boom")
    assert recorder.spans[-1]["status"] == "ERROR"


def test_telemetry_nested_spans_retain_parent_and_snapshot_attributes():
    recorder = TelemetryRecorder("local")
    attributes = {"count": 1}
    with measured_span(recorder, "root") as root_id:
        with measured_span(recorder, "child", attributes=attributes):
            pass
    attributes["count"] = 9
    child, parent = recorder.spans
    assert child["parent_span_id"] == root_id == parent["span_id"]
    assert parent["parent_span_id"] is None
    assert child["attributes"] == {"count": 1}
    with measured_span(recorder, "next"):
        pass
    assert recorder.spans[-1]["parent_span_id"] is None


def test_telemetry_rejects_oversized_attributes_and_invalid_status():
    recorder = TelemetryRecorder("local")
    with pytest.raises(OperationsError, match="bound"):
        recorder.span("large", attributes={"data": "x" * 4096})
    with pytest.raises(OperationsError, match="status"):
        recorder.span("invalid", status="PASS")
    assert recorder.spans == []


def test_vulnerability_and_connector_outputs_are_digest_bound_and_redacted():
    response = vulnerability_response(
        vulnerability="CVE-1",
        severity="high",
        components=["pkg-a"],
        actions=["patch", "notify"],
    )
    assert response["severity"] == "HIGH" and response["response_sha256"]
    event = connector_event(
        target="siem",
        event_type="vulnerability.opened",
        tenant_id="acme",
        subject_digest="a" * 64,
        attributes={"severity": "HIGH"},
    )
    assert event["disclosure"] == "metadata-only"
    assert "raw_evidence" not in event
    with pytest.raises(OperationsError) as error:
        connector_event(
            target="email", event_type="x", tenant_id="acme", subject_digest="a"
        )
    assert error.value.code == "E_CONNECTOR_TARGET"


def test_judge_calibration_reports_confusion_per_split_and_raw_agreement(
    tmp_path: Path,
):
    truth = [["risk"], ["risk"], [], []]
    binding, _ = _calibration_bundle(
        tmp_path,
        case_labels=truth,
        predicted_labels=[["risk"], [], ["risk"], []],
        annotations=[[["risk"], ["risk"]], [["risk"], []], [[], []], [[], []]],
        assignments=["train", "dev", "holdout", "holdout"],
    )

    result = evaluate_judge_calibration(tmp_path, binding)

    assert result["state"] == "OBSERVED_LOCAL_METRICS"
    overall = result["per_category"]["risk"]["overall"]
    assert (overall["tp"], overall["fp"], overall["fn"], overall["tn"]) == (1, 1, 1, 1)
    assert result["split_sizes"] == {"train": 1, "dev": 1, "holdout": 2}
    assert result["per_category"]["risk"]["by_split"]["holdout"]["fp"] == 1
    assert result["per_category"]["risk"]["by_split"]["holdout"]["tn"] == 1
    assert result["raw_annotator_agreement"]["agreement"] == 0.75
    assert result["raw_annotator_agreement"]["cohen_kappa"] == 0.5
    assert result["human_adjudication_disagreements"] == ["case-1"]
    assert result["independence"] == "UNVERIFIED"
    assert result["judge_input_deidentification"] == "UNVERIFIED"
    assert result["holdout_input_exposure"] == "UNVERIFIED"
    assert result["authority"] == "none"
    receipt = {
        key: value for key, value in result.items() if key != "evaluation_sha256"
    }
    assert (
        result["evaluation_sha256"]
        == hashlib.sha256(canonical_json(receipt)).hexdigest()
    )


def test_judge_calibration_empty_negative_labels_and_all_abstentions_are_undefined(
    tmp_path: Path,
):
    binding, _ = _calibration_bundle(
        tmp_path,
        case_labels=[[], []],
        predicted_labels=[[], []],
        abstain_predictions=True,
    )

    result = evaluate_judge_calibration(tmp_path, binding)
    metrics = result["per_category"]["risk"]["overall"]

    assert result["state"] == "OBSERVED_LOCAL_METRICS"
    assert metrics["eligible"] == 2
    assert metrics["judged"] == 0
    assert metrics["coverage"] == 0
    assert metrics["abstentions"] == 2
    assert metrics["positive_abstentions"] == 0
    assert metrics["negative_abstentions"] == 2
    assert metrics["recall"] is None and metrics["precision"] is None
    assert result["raw_annotator_agreement"]["cohen_kappa"] is None
    assert (
        result["raw_annotator_agreement"]["kappa_undefined_reason"] == "constant_labels"
    )


def test_judge_calibration_rejects_cross_split_duplicate_evidence(tmp_path: Path):
    binding, paths = _calibration_bundle(
        tmp_path,
        case_labels=[["risk"], []],
        predicted_labels=[["risk"], []],
        assignments=["train", "holdout"],
    )
    dataset_path = paths["dataset"]
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    dataset["cases"][1]["buggy_source"] = dataset["cases"][0]["buggy_source"]
    dataset_path.write_text(json.dumps(dataset), encoding="utf-8")
    binding["artifacts"]["dataset"]["sha256"] = hashlib.sha256(
        dataset_path.read_bytes()
    ).hexdigest()

    result = evaluate_judge_calibration(tmp_path, binding)

    assert result["state"] == "INCOMPLETE"
    assert result["code"] == "E_CALIBRATION_CROSS_SPLIT_DUPLICATE"


def test_judge_calibration_rejects_prediction_before_split_freeze(tmp_path: Path):
    binding, _ = _calibration_bundle(
        tmp_path,
        case_labels=[["risk"]],
        predicted_labels=[["risk"]],
        predicted_at="2026-10-09T00:00:00+00:00",
    )

    result = evaluate_judge_calibration(tmp_path, binding)

    assert result["state"] == "INCOMPLETE"
    assert result["code"] == "E_CALIBRATION_SPLIT_NOT_FROZEN"


def test_judge_calibration_preserves_low_human_agreement_and_constant_kappa_reason(
    tmp_path: Path,
):
    binding, _ = _calibration_bundle(
        tmp_path,
        case_labels=[["risk"], []],
        predicted_labels=[["risk"], []],
        annotations=[[["risk"], []], [["risk"], []]],
    )
    result = evaluate_judge_calibration(tmp_path, binding)
    assert result["raw_annotator_agreement"]["agreement"] == 0
    assert result["raw_annotator_agreement"]["cohen_kappa"] == 0
    assert result["adjudicated_labels"] == [
        {"case_id": "case-0", "labels": ["risk"], "abstained": False},
        {"case_id": "case-1", "labels": [], "abstained": False},
    ]

    constant_root = tmp_path / "constant"
    constant_root.mkdir()
    constant_binding, _ = _calibration_bundle(
        constant_root,
        case_labels=[["risk"], ["risk"]],
        predicted_labels=[["risk"], ["risk"]],
    )
    constant = evaluate_judge_calibration(constant_root, constant_binding)
    assert constant["raw_annotator_agreement"]["cohen_kappa"] is None
    assert (
        constant["raw_annotator_agreement"]["kappa_undefined_reason"]
        == "constant_labels"
    )
    assert constant["independence"] == "UNVERIFIED"


def test_judge_calibration_rejects_stale_bound_artifact_bytes(tmp_path: Path):
    binding, paths = _calibration_bundle(
        tmp_path,
        case_labels=[["risk"]],
        predicted_labels=[["risk"]],
    )
    assignments = paths["assignments"]
    body = json.loads(assignments.read_text(encoding="utf-8"))
    body["splits"]["case-0"] = "train"
    assignments.write_text(json.dumps(body), encoding="utf-8")

    result = evaluate_judge_calibration(tmp_path, binding)

    assert result["state"] == "INCOMPLETE"
    assert result["errors"][0]["code"] == "TRACE_UNBOUND"


@pytest.mark.parametrize("role", ["model", "prompt", "rubric"])
def test_judge_calibration_rejects_prediction_identity_mismatch(
    tmp_path: Path, role: str
):
    binding, paths = _calibration_bundle(
        tmp_path,
        case_labels=[["risk"]],
        predicted_labels=[["risk"]],
    )
    judgments_path = paths["judgments"]
    judgments = json.loads(judgments_path.read_text(encoding="utf-8"))
    judgments["rows"][0][f"{role}_sha256"] = "0" * 64
    judgments_path.write_text(json.dumps(judgments), encoding="utf-8")
    binding["artifacts"]["judgments"]["sha256"] = hashlib.sha256(
        judgments_path.read_bytes()
    ).hexdigest()

    result = evaluate_judge_calibration(tmp_path, binding)

    assert result["state"] == "INCOMPLETE"
    assert result["code"] == "E_CALIBRATION_ARTIFACT_BINDING"


def _sampling_bundle(root):
    from test_analysis_evidence import _span_fixture

    request, _ = _span_fixture(root)
    binding = request["binding_request"]
    policy = {
        "schema": "factory.trace-sampling-policy.v1",
        "seed": "fixed-seed",
        "fractions": {"low": 1, "medium": 1, "high": 1},
        "max_cost_usd": 1,
        "max_latency_ms": 1000,
        "approval_reference": "approved-policy",
    }
    rows = [
        {
            "schema": "factory.trace-sampling-observation.v1",
            "trace_id": f"trace-{i}",
            "trace_sha256": hashlib.sha256(str(i).encode()).hexdigest(),
            "risk": risk,
            "estimated_cost_usd": 0.1,
            "estimated_latency_ms": 10,
            "actual_cost_usd": 0.1,
            "actual_latency_ms": 10,
            "scored": True,
        }
        for i, risk in enumerate(("low", "medium", "high"))
    ]
    population = {
        "schema": "factory.trace-sampling-population.v1",
        "window_id": "window-1",
        "eligible_count": 3,
        "traces": rows,
    }
    return binding, {"policy": policy, "sampling": population}


def _sampling_write(root, binding, bodies):
    for role, body in bodies.items():
        raw = canonical_json(body)
        (root / f"{role}.json").write_bytes(raw)
        binding["artifacts"][role] = {
            "path": f"{role}.json",
            "sha256": hashlib.sha256(raw).hexdigest(),
        }


def test_sampling_real_bound_population_preserves_denominators(tmp_path):
    from factoryline.operations import evaluate_trace_sampling

    binding, bodies = _sampling_bundle(tmp_path)
    _sampling_write(tmp_path, binding, bodies)
    result = evaluate_trace_sampling(tmp_path, binding)
    assert result["state"] == "OBSERVED_LOCAL_METRICS"
    assert (
        result["eligible"],
        result["selected"],
        result["scored"],
        result["unscored"],
    ) == (3, 3, 3, 0)
    assert all(
        item == {"eligible": 1, "scored": 1} for item in result["by_risk"].values()
    )
    assert result["population_completeness"] == "UNVERIFIED_OUTSIDE_SUPPLIED_WINDOW"
    assert result["authority"] == "none"


@pytest.mark.parametrize(
    "mutation,state",
    [
        ("denominator", "INCOMPLETE"),
        ("duplicate", "INCOMPLETE"),
        ("unknown", "INCOMPLETE"),
        ("budget", "FAIL"),
        ("overspend", "FAIL"),
        ("unscored", "INCOMPLETE"),
        ("unscored_overspend", "FAIL"),
    ],
)
def test_sampling_rejects_missing_usage_or_budget_bypass(tmp_path, mutation, state):
    from factoryline.operations import evaluate_trace_sampling

    binding, bodies = _sampling_bundle(tmp_path)
    population, policy = bodies["sampling"], bodies["policy"]
    if mutation == "denominator":
        population["eligible_count"] = 4
    elif mutation == "duplicate":
        population["traces"][1]["trace_id"] = "trace-0"
    elif mutation == "unknown":
        population["traces"][0]["actual_cost_usd"] = None
    elif mutation == "budget":
        policy["max_cost_usd"] = 0
    elif mutation == "overspend":
        population["traces"][0]["actual_cost_usd"] = 2
    elif mutation == "unscored_overspend":
        population["traces"][0]["actual_cost_usd"] = 2
        population["traces"][0]["scored"] = False
    else:
        population["traces"][0]["scored"] = False
    _sampling_write(tmp_path, binding, bodies)
    result = evaluate_trace_sampling(tmp_path, binding)
    assert result["state"] == state
    assert result["next_actions"]


def _rollout_bundle(root):
    from test_analysis_evidence import _span_fixture

    request, _ = _span_fixture(root)
    binding = request["binding_request"]
    commit = json.loads((root / "candidate.json").read_text())["commit"]
    bodies = {}
    for role, before, after in (
        ("deployment_control", "STAGED", "RUNNING"),
        ("killswitch_control", "ENABLED", "DISABLED"),
        ("rollback_control", "CANDIDATE", "BASELINE"),
    ):
        bodies[role] = {
            "schema": "factory.rollout-control-observation.v1",
            "control": role,
            "target": "authorized-staging",
            "candidate_commit": commit,
            "observed_at": "2026-10-12T10:10:00Z",
            "before": before,
            "after": after,
            "evidence_sha256": binding["sources"][0]["sha256"],
        }
    _sampling_write(root, binding, bodies)
    bodies["rollout"] = {
        "schema": "factory.rollout-evidence.v1",
        "mode": "live",
        "target": "authorized-staging",
        "candidate_commit": commit,
        "window_start": "2026-10-12T10:00:00Z",
        "window_end": "2026-10-12T11:00:00Z",
        "controls": {role: binding["artifacts"][role]["sha256"] for role in bodies},
        "randomization": None,
    }
    return binding, bodies


def test_rollout_evidence_bound_controls_do_not_authorize_promotion(tmp_path):
    from factoryline.operations import evaluate_rollout_evidence

    binding, bodies = _rollout_bundle(tmp_path)
    _sampling_write(tmp_path, binding, bodies)
    result = evaluate_rollout_evidence(tmp_path, binding)
    assert result["state"] == "OBSERVED_LOCAL_CONTROLS"
    assert result["randomization"] is None
    assert not result["promotion_authorized"]
    assert result["producer_authenticity"] == "UNVERIFIED"


@pytest.mark.parametrize(
    "mutation", ["offline", "target", "missing", "transition", "outside", "unbound"]
)
def test_rollout_evidence_rejects_missing_stale_or_offline_controls(tmp_path, mutation):
    from factoryline.operations import evaluate_rollout_evidence

    binding, bodies = _rollout_bundle(tmp_path)
    rollout, kill = bodies["rollout"], bodies["killswitch_control"]
    if mutation == "offline":
        rollout["mode"] = "replay"
    elif mutation == "target":
        kill["target"] = "different-target"
    elif mutation == "missing":
        rollout["controls"].pop("rollback_control")
    elif mutation == "transition":
        kill["after"] = "ENABLED"
    elif mutation == "outside":
        kill["observed_at"] = "2026-10-12T12:00:00Z"
    else:
        kill["evidence_sha256"] = "a" * 64
    _sampling_write(tmp_path, binding, bodies)
    if mutation not in {"offline", "missing"}:
        rollout["controls"]["killswitch_control"] = binding["artifacts"][
            "killswitch_control"
        ]["sha256"]
        _sampling_write(tmp_path, binding, bodies)
    assert evaluate_rollout_evidence(tmp_path, binding)["state"] == "INCOMPLETE"


def test_rollout_evidence_randomization_requires_sticky_unique_assignments():
    from factoryline.operations import _rollout_assignment, OperationsError

    seed = "cohort-seed"
    rows = []
    for index in range(100):
        unit = hashlib.sha256(str(index).encode()).hexdigest()
        rank = (
            int(hashlib.sha256(canonical_json([seed, unit])).hexdigest(), 16) / 2**256
        )
        rows.append(
            {"unit_sha256": unit, "arm": "treatment" if rank < 0.5 else "control"}
        )
    body = {
        "schema": "factory.rollout-randomization.v1",
        "seed": seed,
        "treatment_fraction": 0.5,
        "srm_alpha": 0.01,
        "assignments": rows,
    }
    result = _rollout_assignment(body)
    assert result["units"] == 100
    assert result["statistical_power"] is None
    rows[0]["arm"] = "control" if rows[0]["arm"] == "treatment" else "treatment"
    with pytest.raises(OperationsError):
        _rollout_assignment(body)
