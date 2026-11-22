import hashlib
import json
import sqlite3

import pytest


from factoryline.continuity import ContinuityStore, ContinuityError
from factoryline.engineering_memory import recall_engineering_memory
from factoryline.cli import main
from test_continuity import _record, _principal, PURPOSE, SCOPE


def setup(root, promote=True, name="one", summary=None, evidence_name="proof.json"):
    evidence = root / evidence_name
    evidence.write_text('{"observed":"failed-repair"}')
    store = ContinuityStore(root / ".factory/continuity.sqlite3")
    payload = _record()
    if summary is not None:
        payload["summary"] = summary
    payload["evidence_refs"] = [
        "sha256:"
        + hashlib.sha256(evidence.read_bytes()).hexdigest()
        + ":"
        + evidence_name
    ]
    store.record(
        _principal("writer", ("writer",)), payload, idempotency_key=name, record_id=name
    )
    if promote:
        store.promote(
            _principal("reviewer", ("promoter",)),
            "tenant-a",
            name,
            reason="reviewed evidence",
        )
    return store


def recall(root, scope=SCOPE):
    return recall_engineering_memory(
        root, _principal("reader", ("reader",)), "tenant-a", PURPOSE, scope
    )


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
    store.withdraw(
        _principal("reviewer", ("promoter",)),
        "tenant-a",
        "one",
        status=status,
        reason="new evidence",
        replacement_id=replacement,
    )
    assert all(item["record_id"] != "one" for item in recall(tmp_path)["records"])
    assert store.verify_audit(
        _principal("reader", ("reader",)), "tenant-a", purpose_ref=PURPOSE
    )["valid"]
    # A row-only restoration must not override a withdrawal event.
    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE continuity_records SET status='verified' WHERE record_id='one'"
        )
    assert all(item["record_id"] != "one" for item in recall(tmp_path)["records"])


def test_self_withdrawal_and_invalid_replacement_rejected(tmp_path):
    store = setup(tmp_path)
    with pytest.raises(ContinuityError, match="creator"):
        store.withdraw(
            _principal("writer", ("promoter",)),
            "tenant-a",
            "one",
            status="revoked",
            reason="hide",
        )
    with pytest.raises(ContinuityError):
        store.withdraw(
            _principal("reviewer", ("promoter",)),
            "tenant-a",
            "one",
            status="superseded",
            reason="new",
            replacement_id="one",
        )
    assert len(recall(tmp_path)["records"]) == 1


def test_tenant_and_audit_fail_closed(tmp_path):
    store = setup(tmp_path)
    with pytest.raises(ContinuityError):
        recall_engineering_memory(
            tmp_path, _principal("reader", ("reader",)), "other", PURPOSE, SCOPE
        )
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE continuity_audit_events SET event_hash='bad'")
    with pytest.raises(ContinuityError, match="chain changed"):
        recall(tmp_path)


def test_cli_recall(tmp_path, capsys):
    setup(tmp_path)
    assert (
        main(
            [
                "evidence-memory",
                "--root",
                str(tmp_path),
                "--tenant",
                "tenant-a",
                "--subject",
                "reader",
                "--purpose",
                PURPOSE,
                "--scope",
                SCOPE,
            ]
        )
        == 0
    )
    assert len(json.loads(capsys.readouterr().out)["records"]) == 1


def test_expiry_blocks_influence(tmp_path, monkeypatch):
    setup(tmp_path)
    monkeypatch.setattr(
        "factoryline.engineering_memory._is_expired", lambda value: True
    )
    result = recall(tmp_path)
    assert result["records"] == [] and result["influence_edges"] == []


def test_failed_audit_write_rolls_back_withdrawal(tmp_path, monkeypatch):
    store = setup(tmp_path)

    def fail(*args, **kwargs):
        raise RuntimeError("simulated audit failure")

    monkeypatch.setattr(store, "_audit", fail)
    with pytest.raises(RuntimeError):
        store.withdraw(
            _principal("reviewer", ("promoter",)),
            "tenant-a",
            "one",
            status="revoked",
            reason="review",
        )
    assert len(recall(tmp_path)["records"]) == 1


def test_recall_does_not_write_database(tmp_path):
    store = setup(tmp_path)
    before = store.path.read_bytes()
    recall(tmp_path)
    assert store.path.read_bytes() == before


def test_malformed_audit_payload_has_typed_fail_closed_error(tmp_path):
    store = setup(tmp_path)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE continuity_audit_events SET payload_json='{'")
    with pytest.raises(ContinuityError) as exc:
        recall(tmp_path)
    assert exc.value.code == "E_MEMORY_AUDIT"


def query_recall(root, queries, limit=None):
    return recall_engineering_memory(
        root,
        _principal("reader", ("reader",)),
        "tenant-a",
        PURPOSE,
        SCOPE,
        queries=queries,
        limit=limit,
    )


def test_query_recall_reserves_each_topic_without_writing_or_new_authority(tmp_path):
    for name, text in (
        ("a", "Tenant cache authorization isolation"),
        ("b", "Tenant cache authorization isolation tenant cache"),
        ("c", "Database migration rollback rehearsal"),
        ("d", "User interface contrast"),
    ):
        store = setup(tmp_path, name=name, summary=text)
    before = store.path.read_bytes()
    result = query_recall(tmp_path, ["tenant cache", "migration rollback"], 2)
    assert {row["record_id"] for row in result["records"]} == {"b", "c"}
    trace = result["retrieval"]
    assert trace["status"] == "MATCHED_CONTEXT"
    assert trace["matched"] == 3 and trace["admissible"] == 4
    assert all(
        hop["selected_record_ids"] and hop["gap"] is None for hop in trace["queries"]
    )
    assert result == query_recall(tmp_path, ["tenant cache", "migration rollback"], 2)
    assert trace["authority"] == result["authority"] == "none"
    assert "tenant cache" not in json.dumps(trace)
    assert store.path.read_bytes() == before
    assert {edge["target"] for edge in result["influence_edges"]} == {
        row["record_sha256"] for row in result["records"]
    }


def test_query_recall_reports_budget_and_absence_separately(tmp_path):
    setup(tmp_path, name="a", summary="tenant authorization")
    setup(tmp_path, name="b", summary="migration rollback")
    result = query_recall(tmp_path, ["tenant", "migration", "quasar"], 1)
    trace = result["retrieval"]
    assert trace["status"] == "PARTIAL_CONTEXT"
    assert [hop["gap"] for hop in trace["queries"]] == [
        None,
        "budget_exhausted",
        "no_admissible_lexical_match",
    ]
    assert [row["record_id"] for row in result["records"]] == ["a"]


@pytest.mark.parametrize(
    "status", ["superseded", "contradicted", "revoked", "draft", "changed"]
)
def test_ranking_cannot_rescue_invalid_evidence(tmp_path, status):
    store = setup(
        tmp_path,
        name="bad",
        summary="migration migration migration",
        promote=status != "draft",
        evidence_name="bad-proof.json",
    )
    setup(tmp_path, name="good", summary="migration", evidence_name="good-proof.json")
    if status in {"superseded", "contradicted", "revoked"}:
        store.withdraw(
            _principal("reviewer", ("promoter",)),
            "tenant-a",
            "bad",
            status=status,
            reason="independent correction",
            replacement_id="good" if status == "superseded" else None,
        )
    if status == "changed":
        (tmp_path / "bad-proof.json").write_text("changed")
    result = query_recall(tmp_path, ["migration"])
    assert all(row["record_id"] != "bad" for row in result["records"])
    assert [row["record_id"] for row in result["records"]] == ["good"]
    assert "migration migration" not in json.dumps(result)
    assert all("summary" not in row for row in result["excluded"])


def test_each_topic_uses_next_unselected_candidate_in_same_round(monkeypatch):
    from factoryline import engineering_memory as memory

    monkeypatch.setattr(
        memory, "_recall_rankings", lambda records, queries: [["a", "b"], ["a", "c"]]
    )
    records = [{"record_id": key} for key in "abc"]
    result, trace = memory._balanced_recall(records, (["first", "second"], 2))
    assert [row["record_id"] for row in result] == ["a", "c"]
    assert trace["queries"][1]["selected_record_ids"] == ["a", "c"]


@pytest.mark.parametrize(
    "queries,limit",
    [
        ([], None),
        ([""], None),
        (["!!!"], None),
        (["a\nb"], None),
        (["a"] * 9, None),
        (["a" * 513], None),
        ([True], None),
        (["tenant"], True),
        (["tenant"], 0),
        (["tenant"], 21),
        (None, 1),
    ],
)
def test_query_bounds_reject_before_database_io(tmp_path, queries, limit):
    with pytest.raises(ValueError):
        query_recall(tmp_path, queries, limit)


def test_ascii_del_is_rejected_before_database_io(tmp_path):
    with pytest.raises(ValueError):
        query_recall(tmp_path, ["tenant\x7f"])


@pytest.mark.parametrize("mutation", ["evidence", "withdrawal", "scope", "ledger"])
def test_consecutive_batch_requests_never_reuse_admission(tmp_path, mutation):
    store = setup(tmp_path, summary="tenant rollback")
    assert [
        row["record_id"]
        for row in query_recall(tmp_path, ["tenant", "rollback"])["records"]
    ] == ["one"]
    if mutation == "evidence":
        (tmp_path / "proof.json").write_text("changed")
    elif mutation == "withdrawal":
        store.withdraw(
            _principal("reviewer", ("promoter",)),
            "tenant-a",
            "one",
            status="revoked",
            reason="fresh correction",
        )
    elif mutation == "scope":
        with sqlite3.connect(store.path) as db:
            db.execute("UPDATE continuity_records SET scope_ref='other'")
    else:
        with sqlite3.connect(store.path) as db:
            db.execute("UPDATE continuity_audit_events SET event_hash='corrupted'")
    if mutation == "ledger":
        with pytest.raises(ContinuityError):
            query_recall(tmp_path, ["tenant", "rollback"])
    else:
        result = query_recall(tmp_path, ["tenant", "rollback"])
        assert result["records"] == [] and result["influence_edges"] == []
        assert result["retrieval"]["status"] == "PARTIAL_CONTEXT"


def test_cli_query_recall_and_handoff_cannot_be_silently_narrowed(tmp_path, capsys):
    setup(tmp_path, summary="migration rollback")
    args = [
        "evidence-memory",
        "--root",
        str(tmp_path),
        "--tenant",
        "tenant-a",
        "--subject",
        "reader",
        "--purpose",
        PURPOSE,
        "--scope",
        SCOPE,
    ]
    assert (
        main([*args, "--query", "migration", "--query", "quasar", "--limit", "1"]) == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["retrieval"]["status"] == "PARTIAL_CONTEXT"
    assert len(result["records"]) == 1
    assert main([*args, "--query", "migration", "--sender", "forgeline"]) == 1
    assert json.loads(capsys.readouterr().out)["authority"] == "none"


def test_batch_recall_fixed_complete_trace_and_single_shared_call(monkeypatch):
    from factoryline import audit_rule_search as search, engineering_memory as memory

    calls = []
    original = search._bm25_scores_batch

    def observed(rules, queries, *, fielded):
        calls.append((len(rules), list(queries), fielded))
        return original(rules, queries, fielded=fielded)

    monkeypatch.setattr(search, "_bm25_scores_batch", observed)
    rows = [
        {
            "record_id": "a",
            "summary": "tenant cache",
            "evidence": [{"path": "one.json"}],
        },
        {"record_id": "b", "summary": "rollback", "evidence": [{"path": "two.json"}]},
    ]
    selected, trace = memory._balanced_recall(
        rows, (["tenant", "rollback", "quasar"], 2)
    )
    assert selected == rows
    assert calls == [(2, ["tenant", "rollback", "quasar"], True)]
    assert trace == {
        "schema": "factory.evidence-recall-selection.v1",
        "method": "trust-first-bm25f-round-robin",
        "limit": 2,
        "admissible": 2,
        "matched": 2,
        "authority": "none",
        "status": "PARTIAL_CONTEXT",
        "claim_boundary": "Lexical context matches, not semantic completeness, defect recall or proof authority.",
        "queries": [
            {
                "query_sha256": "da048eda4e78177117649659a8517977d116dfc0f72643eea55f87a528990b4d",
                "matched": 1,
                "selected_record_ids": ["a"],
                "gap": None,
            },
            {
                "query_sha256": "3770b198a03f18cbf37a3bfd4eba2fbbab9ea2eb9795b207678b45c957a6ce18",
                "matched": 1,
                "selected_record_ids": ["b"],
                "gap": None,
            },
            {
                "query_sha256": "b02c69f5565815b842073bb3e0266e00c1b2702169942cb0c7fa97804c34cdf2",
                "matched": 0,
                "selected_record_ids": [],
                "gap": "no_admissible_lexical_match",
            },
        ],
        "selection_sha256": "8dfe1920d7e6a5431b09dad3c9e2447950157a97096de684a002c5a2ea561079",
    }
