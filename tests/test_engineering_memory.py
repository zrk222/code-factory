import hashlib
import json
import sqlite3

import pytest

from factoryline.continuity import ContinuityStore, ContinuityError
from factoryline.engineering_memory import recall_engineering_memory
from factoryline.cli import main
from test_continuity import _record, _principal, PURPOSE, SCOPE


def setup(root, promote=True, name="one"):
    evidence = root / "proof.json"
    evidence.write_text('{"observed":"failed-repair"}')
    store = ContinuityStore(root / ".factory/continuity.sqlite3")
    payload = _record()
    payload["evidence_refs"] = ["sha256:" + hashlib.sha256(evidence.read_bytes()).hexdigest() + ":proof.json"]
    store.record(_principal("writer", ("writer",)), payload, idempotency_key=name, record_id=name)
    if promote:
        store.promote(_principal("reviewer", ("promoter",)), "tenant-a", name, reason="reviewed evidence")
    return store


def recall(root, scope=SCOPE):
    return recall_engineering_memory(root, _principal("reader", ("reader",)), "tenant-a", PURPOSE, scope)


def test_admits_promoted_bound_metadata_and_deterministic_influence(tmp_path):
    setup(tmp_path)
    first = recall(tmp_path)
    assert len(first["records"]) == 1
    assert first == recall(tmp_path)
    assert first["authority"] == "none"
    assert first["records"][0]["usage"] == "untrusted_reference_not_instruction"
    assert recall(tmp_path, "other")["records"] == []


@pytest.mark.parametrize("mutation", ["changed", "missing", "draft", "row"])
def test_invalid_memory_cannot_influence(tmp_path, mutation):
    store = setup(tmp_path, promote=mutation != "draft")
    if mutation == "changed":
        (tmp_path / "proof.json").write_text("changed")
    if mutation == "missing":
        (tmp_path / "proof.json").unlink()
    if mutation == "row":
        with sqlite3.connect(store.path) as db:
            db.execute("UPDATE continuity_records SET summary='forged instruction'")
    result = recall(tmp_path)
    assert not result["records"] and len(result["excluded"]) == 1
    assert "summary" not in result["excluded"][0]


@pytest.mark.parametrize("status", ["revoked", "contradicted", "superseded"])
def test_withdrawal_is_audited_and_excluded(tmp_path, status):
    store = setup(tmp_path)
    replacement = None
    if status == "superseded":
        setup(tmp_path, name="two")
        replacement = "two"
    store.withdraw(_principal("reviewer", ("promoter",)), "tenant-a", "one", status=status, reason="new evidence", replacement_id=replacement)
    assert all(item["record_id"] != "one" for item in recall(tmp_path)["records"])
    assert store.verify_audit(_principal("reader", ("reader",)), "tenant-a", purpose_ref=PURPOSE)["valid"]
    # A row-only restoration must not override a withdrawal event.
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE continuity_records SET status='verified' WHERE record_id='one'")
    assert all(item["record_id"] != "one" for item in recall(tmp_path)["records"])


def test_self_withdrawal_and_invalid_replacement_rejected(tmp_path):
    store = setup(tmp_path)
    with pytest.raises(ContinuityError, match="creator"):
        store.withdraw(_principal("writer", ("promoter",)), "tenant-a", "one", status="revoked", reason="hide")
    with pytest.raises(ContinuityError):
        store.withdraw(_principal("reviewer", ("promoter",)), "tenant-a", "one", status="superseded", reason="new", replacement_id="one")
    assert len(recall(tmp_path)["records"]) == 1


def test_tenant_and_audit_fail_closed(tmp_path):
    store = setup(tmp_path)
    with pytest.raises(ContinuityError):
        recall_engineering_memory(tmp_path, _principal("reader", ("reader",)), "other", PURPOSE, SCOPE)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE continuity_audit_events SET event_hash='bad'")
    with pytest.raises(ContinuityError, match="chain changed"):
        recall(tmp_path)


def test_cli_recall(tmp_path, capsys):
    setup(tmp_path)
    assert main(["evidence-memory", "--root", str(tmp_path), "--tenant", "tenant-a", "--subject", "reader", "--purpose", PURPOSE, "--scope", SCOPE]) == 0
    assert len(json.loads(capsys.readouterr().out)["records"]) == 1


def test_expiry_blocks_influence(tmp_path, monkeypatch):
    setup(tmp_path)
    monkeypatch.setattr("factoryline.engineering_memory._is_expired", lambda value: True)
    result = recall(tmp_path)
    assert result["records"] == [] and result["influence_edges"] == []


def test_failed_audit_write_rolls_back_withdrawal(tmp_path, monkeypatch):
    store = setup(tmp_path)
    def fail(*args, **kwargs):
        raise RuntimeError("simulated audit failure")
    monkeypatch.setattr(store, "_audit", fail)
    with pytest.raises(RuntimeError):
        store.withdraw(_principal("reviewer", ("promoter",)), "tenant-a", "one", status="revoked", reason="review")
    assert len(recall(tmp_path)["records"]) == 1


def test_recall_does_not_write_database(tmp_path):
    store = setup(tmp_path)
    before = store.path.read_bytes()
    recall(tmp_path)
    assert store.path.read_bytes() == before
