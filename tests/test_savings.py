from __future__ import annotations

import json

import pytest

from factoryline.savings import (
    SavingsError,
    export_public_savings_report,
    public_savings_report,
    record_savings_pair,
)
from factoryline.cli import main


def test_exact_pair_computes_signed_time_token_and_cost_savings(tmp_path):
    evidence = tmp_path / "validation.json"
    evidence.write_text('{"equivalent": true}', encoding="utf-8")
    result = record_savings_pair(
        tmp_path,
        "checkout-2026-07-25",
        {"elapsed_ms": 600_000, "tokens": 12_000, "cost_usd": 6.0},
        {"elapsed_ms": 300_000, "tokens": 8_000, "cost_usd": 4.0},
        equivalent_outcome=True,
        evidence=evidence,
    )
    assert result["savings"]["time_saved_ms"] == 300_000
    assert result["savings"]["time_savings_rate"] == 0.5
    assert result["savings"]["tokens_saved"] == 4_000
    assert result["savings"]["cost_saved_usd"] == 2.0
    assert result["savings"]["productivity_gain_rate"] == 1.0
    assert result["equivalence"]["evidence_sha256"]
    assert "PRODUCTIVITY_GAIN_EXACT" in result["markers"]


def test_productivity_is_withheld_without_equivalence_and_unknowns_remain_null(tmp_path):
    result = record_savings_pair(
        tmp_path, "unknown-fields",
        {"elapsed_ms": 2000}, {"elapsed_ms": 1000},
    )
    assert result["savings"]["tokens_saved"] is None
    assert result["savings"]["cost_saved_usd"] is None
    assert result["savings"]["productivity_gain_rate"] is None
    assert "UNKNOWN_PAIR_FIELD_PRESERVED" in result["markers"]
    assert "PRODUCTIVITY_GAIN_WITHHELD" in result["markers"]


def test_negative_savings_are_visible_and_never_clamped(tmp_path):
    evidence = tmp_path / "same.txt"
    evidence.write_text("same accepted output", encoding="utf-8")
    result = record_savings_pair(
        tmp_path, "regression",
        {"elapsed_ms": 100, "tokens": 10, "cost_usd": 1},
        {"elapsed_ms": 200, "tokens": 20, "cost_usd": 2},
        equivalent_outcome=True, evidence=evidence,
    )
    assert result["savings"]["time_saved_ms"] == -100
    assert result["savings"]["tokens_saved"] == -10
    assert result["savings"]["productivity_gain_rate"] == -0.5
    report = public_savings_report(tmp_path)
    assert report["time"]["saved_total"] == -100
    assert report["tokens"]["saved_total"] == -10
    assert "SAVINGS_NEGATIVE_VISIBLE" in report["markers"]


def test_pair_validation_overwrite_and_evidence_fail_closed(tmp_path):
    with pytest.raises(SavingsError, match="pair id"):
        record_savings_pair(tmp_path, "../bad", {"elapsed_ms": 1}, {"elapsed_ms": 1})
    record_savings_pair(tmp_path, "one", {"elapsed_ms": 1}, {"elapsed_ms": 1})
    with pytest.raises(SavingsError) as error:
        record_savings_pair(tmp_path, "one", {"elapsed_ms": 1}, {"elapsed_ms": 1})
    assert error.value.code == "PAIR_OVERWRITE_REFUSED"
    with pytest.raises(SavingsError) as error:
        record_savings_pair(
            tmp_path, "two", {"elapsed_ms": 1}, {"elapsed_ms": 1},
            equivalent_outcome=True, evidence=tmp_path / "missing",
        )
    assert error.value.code == "EQUIVALENCE_EVIDENCE_REQUIRED"


def test_public_report_is_aggregate_safe_and_exported_atomically(tmp_path):
    evidence = tmp_path / "private-evidence.json"
    evidence.write_text("same", encoding="utf-8")
    record_savings_pair(
        tmp_path, "private-feature-name",
        {"elapsed_ms": 100, "tokens": 50},
        {"elapsed_ms": 80, "tokens": 40},
        equivalent_outcome=True, evidence=evidence,
    )
    report = public_savings_report(tmp_path)
    assert report["pairs"] == 1
    assert report["time"]["saved_total"] == 20
    assert report["tokens"]["weighted_savings_rate"] == 0.2
    encoded = json.dumps(report)
    for private in ("private-feature-name", str(tmp_path), "private-evidence", "evidence_sha256", "pair_id"):
        assert private not in encoded
    output = tmp_path / "public.json"
    assert export_public_savings_report(tmp_path, output) == output.resolve()
    assert json.loads(output.read_text(encoding="utf-8"))["schema"] == "factory.savings-report.public.v1"


def test_savings_cli_records_and_exports_exact_pair(tmp_path, capsys):
    assert main([
        "savings", "record", "cli-pair", "--root", str(tmp_path),
        "--baseline-elapsed-ms", "1000", "--factory-elapsed-ms", "750",
        "--baseline-tokens", "100", "--factory-tokens", "80", "--json",
    ]) == 0
    recorded = json.loads(capsys.readouterr().out)
    assert recorded["marker"] == "SAVINGS_PAIR_RECEIPTED"
    assert recorded["savings"]["time_saved_ms"] == 250
    output = tmp_path / "sample.json"
    assert main(["savings", "report", "--root", str(tmp_path), "--out", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["tokens"]["saved_total"] == 20


def test_savings_cli_refuses_unproven_equivalence(tmp_path, capsys):
    assert main([
        "savings", "record", "invalid", "--root", str(tmp_path),
        "--baseline-elapsed-ms", "100", "--factory-elapsed-ms", "50",
        "--equivalent-outcome", "--json",
    ]) == 2
    failure = json.loads(capsys.readouterr().err)
    assert failure["code"] == "EQUIVALENCE_EVIDENCE_REQUIRED"
