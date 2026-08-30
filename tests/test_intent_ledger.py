from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.intent_ledger import IntentLedgerError, capture_intent_ledger, inspect_intent_ledger, validate_intent_ledger_record
from factoryline.proof_reuse import record_proof


def _files(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def _capture(root: Path, changed: list[str] | None = None) -> dict:
    return capture_intent_ledger(
        root,
        change_list="Billing cancellation",
        changed=changed or ["app/billing.py"],
        confirmed_by="Ada",
        promise="Cancelled accounts never receive a new invoice.",
        non_goal="This change does not migrate historical invoices.",
        failure_case="A cancelled account receiving an invoice must fail the declared negative proof.",
        confirmation="CAPTURE Billing cancellation",
    )


def _review(*, paths: list[str], stale: list[str] | None = None, coverage: bool = True) -> dict:
    return {
        "input_source": "explicit",
        "changed_paths": paths,
        "review_sha256": "a" * 64,
        "unproven_claims": [],
        "coverage": {"ok": coverage, "uncovered": ["REQ-1"] if not coverage else []},
        "impact": {"rerun_proofs": [{"proof_id": item} for item in stale or []], "unmatched_changed_paths": []},
    }


def test_capture_records_only_confirmed_local_metadata(tmp_path: Path) -> None:
    result = _capture(tmp_path)

    assert result["marker"] == "INTENT_LEDGER_CAPTURED"
    assert result["authority"]["record_write"] is True
    assert all(value is False for key, value in result["authority"].items() if key != "record_write")
    path = tmp_path / result["path"]
    assert path.is_file()
    assert validate_intent_ledger_record(json.loads(path.read_text(encoding="utf-8"))) == result["record"]


def test_capture_rejects_missing_exact_confirmation_without_writing(tmp_path: Path) -> None:
    before = _files(tmp_path)
    with pytest.raises(IntentLedgerError) as exc:
        capture_intent_ledger(
            tmp_path, change_list="Billing cancellation", changed=["app/billing.py"], confirmed_by="Ada",
            promise="Promise", non_goal="Non-goal", failure_case="Failure case", confirmation="yes",
        )
    assert exc.value.code == "INTENT_LEDGER_CONFIRMATION_REQUIRED"
    assert _files(tmp_path) == before


def test_capture_rejects_vague_promise_even_with_exact_confirmation(tmp_path: Path) -> None:
    with pytest.raises(IntentLedgerError) as exc:
        capture_intent_ledger(
            tmp_path, change_list="Billing cancellation", changed=["app/billing.py"], confirmed_by="Ada",
            promise="Make it better.", non_goal="No historical migration.",
            failure_case="A cancelled account receiving an invoice fails.",
            confirmation="CAPTURE Billing cancellation",
        )
    assert exc.value.code == "INTENT_LEDGER_INTENT_UNCLEAR"
    assert not (tmp_path / ".factory" / "intent-ledgers").exists()


def test_inspection_is_read_only_and_returns_uncontracted_without_inventing_intent(tmp_path: Path) -> None:
    before = _files(tmp_path)
    inspection = inspect_intent_ledger(tmp_path, change_list="Billing cancellation", changed=["app/billing.py"])

    assert inspection["state"] == "uncontracted"
    assert inspection["next_action"]["action"] == "capture_intent"
    assert inspection["record"] is None
    assert inspection["authority"]["record_write"] is False
    assert all(value is False for value in inspection["authority"].values())
    assert _files(tmp_path) == before


def test_scope_escape_precedes_lower_priority_change_review_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _capture(tmp_path)
    monkeypatch.setattr("factoryline.intent_ledger.review_change", lambda *_args, **_kwargs: _review(paths=["app/billing.py", "app/invoices.py"], stale=["proof-1"], coverage=False))

    inspection = inspect_intent_ledger(tmp_path, change_list="Billing cancellation", changed=["app/billing.py", "app/invoices.py"])

    assert inspection["state"] == "scope_escape"
    assert inspection["findings"][0]["facts"]["paths"] == ["app/invoices.py"]
    assert inspection["next_action"]["action"] == "amend_or_split_change_list"


def test_stale_proof_uses_existing_change_review_without_executing_a_gate(tmp_path: Path) -> None:
    (tmp_path / "input.txt").write_text("before", encoding="utf-8")
    (tmp_path / "output.txt").write_text("green", encoding="utf-8")
    record_proof(tmp_path, {"name": "unit", "command": ["python", "-m", "pytest"], "read_only": True, "inputs": ["input.txt"], "outputs": ["output.txt"]}, elapsed_ms=50)
    (tmp_path / "input.txt").write_text("after", encoding="utf-8")
    _capture(tmp_path, ["input.txt"])
    before = _files(tmp_path)

    inspection = inspect_intent_ledger(tmp_path, change_list="Billing cancellation", changed=["input.txt"])

    assert inspection["state"] == "stale_proof"
    assert inspection["next_action"]["action"] == "rerun_stale_proof"
    assert inspection["change_review"]["stale_proof_ids"]
    assert _files(tmp_path) == before


def test_coverage_gap_and_ready_state_are_deterministic_from_explicit_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _capture(tmp_path)
    monkeypatch.setattr("factoryline.intent_ledger.review_change", lambda *_args, **_kwargs: _review(paths=["app/billing.py"], coverage=False))
    gap = inspect_intent_ledger(tmp_path, change_list="Billing cancellation", changed=["app/billing.py"])
    assert gap["state"] == "coverage_incomplete"

    monkeypatch.setattr("factoryline.intent_ledger.review_change", lambda *_args, **_kwargs: _review(paths=["app/billing.py"]))
    ready = inspect_intent_ledger(tmp_path, change_list="Billing cancellation", changed=["app/billing.py"])
    assert ready["state"] == "ready_for_human_review"
    assert ready["next_action"]["action"] == "review_packet"
    assert inspect_intent_ledger(tmp_path, change_list="Billing cancellation", changed=["app/billing.py"])["inspection_sha256"] == ready["inspection_sha256"]


def test_latest_tampered_record_fails_closed_without_fallback(tmp_path: Path) -> None:
    first = _capture(tmp_path)
    second = _capture(tmp_path)
    assert first["path"] != second["path"]
    (tmp_path / second["path"]).write_text("{}", encoding="utf-8")

    inspection = inspect_intent_ledger(tmp_path, change_list="Billing cancellation", changed=["app/billing.py"])

    assert inspection["state"] == "intent_ledger_invalid"
    assert inspection["record"] is None
    assert inspection["record_path"] == second["path"]


def test_identical_clock_tick_captures_never_overwrite_each_other(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("factoryline.intent_ledger.time.time_ns", lambda: 42)

    first = _capture(tmp_path)
    second = _capture(tmp_path)

    assert first["path"] != second["path"]
    assert (tmp_path / first["path"]).is_file()
    assert (tmp_path / second["path"]).is_file()
    assert len(list((tmp_path / ".factory" / "intent-ledgers").glob("*.json"))) == 2


def test_cli_capture_and_read_only_inspection_are_machine_readable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    capture_args = [
        "intent", "capture", "--root", str(tmp_path), "--change-list", "Billing cancellation", "--changed", "app/billing.py",
        "--confirmed-by", "Ada", "--promise", "Cancelled accounts never receive a new invoice.",
        "--non-goal", "No historical migration.", "--failure-case", "Invoice creation for a cancelled account fails.",
        "--confirmation", "CAPTURE Billing cancellation", "--json",
    ]
    assert main(capture_args) == 0
    captured = json.loads(capsys.readouterr().out)
    before = _files(tmp_path)

    assert main(["intent", "inspect", "--root", str(tmp_path), "--change-list", "Billing cancellation", "--changed", "app/billing.py", "--json"]) == 0
    inspection = json.loads(capsys.readouterr().out)
    assert captured["marker"] == "INTENT_LEDGER_CAPTURED"
    assert inspection["state"] in {"coverage_incomplete", "scope_escape", "ready_for_human_review"}
    assert _files(tmp_path) == before
