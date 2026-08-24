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


PURPOSE = "delivery-review@1"
SCOPE = "repo:sha256:abc123"


def _principal(subject: str, roles: tuple[str, ...]) -> ContinuityPrincipal:
    return ContinuityPrincipal(subject=subject, tenant_id="tenant-a", roles=roles, purposes=(PURPOSE,))


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
        "expires_at": expires_at or (datetime.now(timezone.utc) + timedelta(days=3)).isoformat(),
    }


def test_continuity_requires_independent_promotion_and_exact_scope_purpose(tmp_path: Path):
    store = ContinuityStore(tmp_path / "continuity.sqlite3")
    created = store.record(_principal("worker", ("writer",)), _record(), idempotency_key="intent-1", record_id="record-1")
    assert created["status"] == "draft"

    before = store.recall(_principal("reader", ("reader",)), "tenant-a", purpose_ref=PURPOSE, scope_ref=SCOPE)
    assert before["records"] == []

    with pytest.raises(ContinuityError) as self_promotion:
        store.promote(_principal("worker", ("promoter",)), "tenant-a", "record-1", reason="self review")
    assert self_promotion.value.code == "E_SELF_PROMOTION"

    promoted = store.promote(_principal("reviewer", ("promoter",)), "tenant-a", "record-1", reason="receipt and ADR independently reviewed")
    assert promoted["status"] == "verified"
    assert promoted["promoted_by"] == "reviewer"

    recalled = store.recall(_principal("reader", ("reader",)), "tenant-a", purpose_ref=PURPOSE, scope_ref=SCOPE)
    assert recalled["marker"] == "CONTINUITY_RECALL_SCOPE_AND_PURPOSE_EXACT"
    assert [item["record_id"] for item in recalled["records"]] == ["record-1"]

    wrong_scope = store.recall(_principal("reader", ("reader",)), "tenant-a", purpose_ref=PURPOSE, scope_ref="repo:sha256:other")
    assert wrong_scope["records"] == []
    wrong_purpose = ContinuityPrincipal("reader", "tenant-a", ("reader",), ("incident-response@1",))
    with pytest.raises(ContinuityError) as denied:
        store.recall(wrong_purpose, "tenant-a", purpose_ref=PURPOSE, scope_ref=SCOPE)
    assert denied.value.code == "E_PURPOSE_DENIED"


def test_continuity_rejects_content_store_and_conflicting_idempotency(tmp_path: Path):
    store = ContinuityStore(tmp_path / "continuity.sqlite3")
    payload = _record()
    payload["content"] = "do not put source or memory bodies in this ledger"
    with pytest.raises(ContinuityError) as forbidden:
        store.record(_principal("writer", ("writer",)), payload, idempotency_key="content")
    assert forbidden.value.code == "E_CONTENT_STORE_FORBIDDEN"

    stable_payload = _record()
    saved = store.record(_principal("writer", ("writer",)), stable_payload, idempotency_key="stable", record_id="stable-record")
    replay = store.record(_principal("writer", ("writer",)), stable_payload, idempotency_key="stable", record_id="stable-record")
    assert replay["record_sha256"] == saved["record_sha256"]
    changed = _record(scope="repo:sha256:changed")
    with pytest.raises(ContinuityError) as conflict:
        store.record(_principal("writer", ("writer",)), changed, idempotency_key="stable")
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
def test_continuity_rejects_incomplete_metadata_before_any_record_or_audit_write(tmp_path: Path, field: str, value: object):
    db_path = tmp_path / "continuity.sqlite3"
    store = ContinuityStore(db_path)
    payload = _record()
    payload[field] = value
    with pytest.raises(ContinuityError):
        store.record(_principal("writer", ("writer",)), payload, idempotency_key=f"invalid-{field}")
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM continuity_records").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM continuity_audit_events").fetchone()[0] == 0

    with pytest.raises(ContinuityError) as missing_idempotency:
        store.record(_principal("writer", ("writer",)), _record(), idempotency_key="")
    assert missing_idempotency.value.code == "E_IDEMPOTENCY_REQUIRED"


def test_continuity_record_rolls_back_when_the_audit_append_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "continuity.sqlite3"
    store = ContinuityStore(db_path)

    def fail_audit(*_args, **_kwargs):
        raise RuntimeError("simulated audit storage failure")

    monkeypatch.setattr(store, "_audit", fail_audit)
    with pytest.raises(RuntimeError, match="simulated audit storage failure"):
        store.record(_principal("writer", ("writer",)), _record(), idempotency_key="rollback")
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM continuity_records").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM continuity_audit_events").fetchone()[0] == 0


def test_continuity_promotion_rejects_tenant_purpose_expiry_and_repeat_attempts(tmp_path: Path):
    db_path = tmp_path / "continuity.sqlite3"
    store = ContinuityStore(db_path)
    store.record(_principal("writer", ("writer",)), _record(), idempotency_key="promotion", record_id="promotion-record")

    other_tenant = ContinuityPrincipal("reviewer", "tenant-b", ("promoter",), (PURPOSE,))
    with pytest.raises(ContinuityError) as denied_tenant:
        store.promote(other_tenant, "tenant-a", "promotion-record", reason="cross-tenant")
    assert denied_tenant.value.code == "E_TENANT_BOUNDARY"

    wrong_purpose = ContinuityPrincipal("reviewer", "tenant-a", ("promoter",), ("incident-response@1",))
    with pytest.raises(ContinuityError) as denied_purpose:
        store.promote(wrong_purpose, "tenant-a", "promotion-record", reason="wrong-purpose")
    assert denied_purpose.value.code == "E_PURPOSE_DENIED"

    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE continuity_records SET expires_at = ? WHERE record_id = ?", ("2020-01-01T00:00:00Z", "promotion-record"))
        db.commit()
    with pytest.raises(ContinuityError) as expired:
        store.promote(_principal("reviewer", ("promoter",)), "tenant-a", "promotion-record", reason="expired")
    assert expired.value.code == "E_RECORD_EXPIRED"

    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE continuity_records SET expires_at = ? WHERE record_id = ?", (_record()["expires_at"], "promotion-record"))
        db.commit()
    store.promote(_principal("reviewer", ("promoter",)), "tenant-a", "promotion-record", reason="valid")
    with pytest.raises(ContinuityError) as repeat:
        store.promote(_principal("second-reviewer", ("promoter",)), "tenant-a", "promotion-record", reason="again")
    assert repeat.value.code == "E_ALREADY_PROMOTED"


def test_continuity_withholds_expired_records_and_detects_audit_tampering(tmp_path: Path):
    db_path = tmp_path / "continuity.sqlite3"
    store = ContinuityStore(db_path)
    store.record(_principal("writer", ("writer",)), _record(), idempotency_key="expires", record_id="expiring")
    store.promote(_principal("reviewer", ("promoter",)), "tenant-a", "expiring", reason="reviewed")
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE continuity_records SET expires_at = ? WHERE record_id = ?", ("2020-01-01T00:00:00Z", "expiring"))
        db.commit()
    recalled = store.recall(_principal("reader", ("reader",)), "tenant-a", purpose_ref=PURPOSE, scope_ref=SCOPE)
    assert recalled["records"] == []
    assert recalled["withheld_expired_record_ids"] == ["expiring"]

    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE continuity_audit_events SET payload_json = ?", (json.dumps({"tampered": True}),))
        db.commit()
    proof = store.prove(_principal("reader", ("reader",)), "tenant-a", "expiring")
    assert proof["audit"]["valid"] is False


def test_graph_ops_projects_redacted_continuity_metadata_without_writing(tmp_path: Path):
    db_path = tmp_path / ".factory" / "continuity.sqlite3"
    store = ContinuityStore(db_path)
    store.record(_principal("worker", ("writer",)), _record(), idempotency_key="graph", record_id="graph-record")
    store.promote(_principal("reviewer", ("promoter",)), "tenant-a", "graph-record", reason="reviewed")
    before = db_path.read_bytes()
    graph = graph_ops_snapshot(tmp_path)
    after = db_path.read_bytes()
    assert after == before
    assert "GRAPH_OPS_CONTINUITY_METADATA_READ_ONLY" in graph["markers"]
    assert graph["facts"]["continuity_verified_current_count"] == 1
    record = next(item for item in graph["nodes"] if item["id"] == "continuity:graph-record")
    assert "memory_ref" not in record["facts"]
    assert "summary" not in record["facts"]
    assert graph["authority"]["publication"] is False
    page = graph_ops_html("local-token")
    assert "Factory Continuity · Decision Replay" in page
    assert "memory contents displayed" in page
    assert "promote-continuity" in page and "disabled" in page


def test_continuity_projection_is_bounded_redacted_and_principal_args_normalize(tmp_path: Path):
    db_path = tmp_path / ".factory" / "continuity.sqlite3"
    store = ContinuityStore(db_path)
    store.record(_principal("writer", ("writer",)), _record(), idempotency_key="projected", record_id="projected")
    projection = continuity_projection(tmp_path)
    principal = principal_from_args("reader", "tenant-a", ["reader", " reader "], [PURPOSE, " "])
    assert principal.roles == ("reader",)
    assert principal.purposes == (PURPOSE,)
    assert projection["available"] is True
    assert projection["records"][0]["record_id"] == "projected"
    assert projection["records"][0]["effective_status"] == "draft"
    assert "memory_ref" not in projection["records"][0]
    assert "summary" not in projection["records"][0]


def test_top_level_continuity_adapters_keep_the_store_as_the_single_boundary(tmp_path: Path):
    store = ContinuityStore(tmp_path / "continuity.sqlite3")
    writer = _principal("writer", ("writer",))
    record = record_continuity(store, writer, _record(), "adapter-record")
    promoted = promote_continuity(store, _principal("reviewer", ("promoter",)), "tenant-a", record["record_id"], "reviewed")
    recalled = recall_continuity(store, _principal("reader", ("reader",)), "tenant-a", PURPOSE, SCOPE)
    assert promoted["status"] == "verified"
    assert recalled["records"][0]["record_id"] == record["record_id"]


def test_cli_continuity_flow_is_local_and_explicit(tmp_path: Path, capsys):
    db = tmp_path / "continuity.sqlite3"
    payload = tmp_path / "record.json"
    payload.write_text(json.dumps(_record()), encoding="utf-8")
    assert main(["continuity", "init", "--db", str(db)]) == 0
    capsys.readouterr()
    assert main([
        "continuity", "record", str(payload), "--idempotency-key", "cli-1", "--record-id", "cli-record",
        "--db", str(db), "--tenant", "tenant-a", "--subject", "worker", "--roles", "writer", "--purposes", PURPOSE,
    ]) == 0
    created = json.loads(capsys.readouterr().out)
    assert created["status"] == "draft"
    assert main([
        "continuity", "promote", "cli-record", "--reason", "independent review", "--db", str(db), "--tenant", "tenant-a",
        "--subject", "reviewer", "--roles", "promoter", "--purposes", PURPOSE,
    ]) == 0
    capsys.readouterr()
    assert main([
        "continuity", "recall", "--purpose", PURPOSE, "--scope", SCOPE, "--db", str(db), "--tenant", "tenant-a",
        "--subject", "reader", "--roles", "reader", "--purposes", PURPOSE,
    ]) == 0
    recalled = json.loads(capsys.readouterr().out)
    assert recalled["records"][0]["record_id"] == "cli-record"
