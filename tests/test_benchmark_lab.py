import hashlib
import json
from pathlib import Path
import pytest

from factoryline.benchmark_lab import (
    BenchmarkError,
    CLEAN_FINDING,
    SCHEMA,
    evaluate_benchmark,
    validate_benchmark_manifest,
    run_public_benchmark,
)


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _case(case_id: str, *, clean: bool = False, category: str = "stateful_invariant"):
    return {
        "id": case_id,
        "category": category,
        "source": f"fixtures/{case_id}",
        "source_sha256": _digest("a" + case_id[0]),
        "expected_finding": CLEAN_FINDING if clean else "refund-over-capture",
        "replay_argv": ["python", "-m", "pytest", f"tests/{case_id}.py"],
        "buggy_sha256": _digest("b" + case_id[0]),
        "fixed_sha256": _digest("c" + case_id[0]),
    }


def test_benchmark_passes_real_defect_and_clean_control_with_metrics():
    manifest = {
        "schema": SCHEMA,
        "benchmark_id": "senior-fixtures",
        "version": "1",
        "cases": [
            _case("refund"),
            _case("clean", clean=True, category="tenant_isolation"),
        ],
    }
    observations = {
        "refund": {
            "buggy": {"state": "FAIL", "finding": "refund-over-capture"},
            "fixed": {"state": "PASS", "finding": ""},
        },
        "clean": {
            "buggy": {"state": "PASS", "finding": ""},
            "fixed": {"state": "PASS", "finding": ""},
        },
    }
    receipt = evaluate_benchmark(manifest, observations)
    assert receipt["decision"] == "PASS"
    assert receipt["metrics"]["stateful_invariant"]["recall"] == 1.0
    assert receipt["metrics"]["tenant_isolation"]["tn"] == 1
    assert receipt["authority"] == "none"


def test_wrong_finding_blocks_with_replay_data():
    manifest = {
        "schema": SCHEMA,
        "benchmark_id": "senior-fixtures",
        "version": "1",
        "cases": [_case("refund")],
    }
    observations = {
        "refund": {
            "buggy": {"state": "PASS", "finding": ""},
            "fixed": {"state": "PASS", "finding": ""},
        }
    }
    receipt = evaluate_benchmark(manifest, observations)
    assert receipt["decision"] == "BLOCKED"
    assert receipt["cases"][0]["replay_argv"][0] == "python"
    assert receipt["metrics"]["stateful_invariant"]["fn"] == 1


def test_manifest_rejects_urls_duplicates_and_unknown_category():
    base = {
        "schema": SCHEMA,
        "benchmark_id": "x",
        "version": "1",
        "cases": [_case("a")],
    }
    bad_url = {**base, "cases": [{**_case("a"), "source": "https://example.test/bug"}]}
    with pytest.raises(BenchmarkError, match="E_BENCHMARK_SOURCE"):
        validate_benchmark_manifest(bad_url)
    with pytest.raises(BenchmarkError, match="duplicate case"):
        validate_benchmark_manifest({**base, "cases": [_case("a"), _case("a")]})
    with pytest.raises(BenchmarkError, match="E_BENCHMARK_CATEGORY"):
        validate_benchmark_manifest(
            {**base, "cases": [{**_case("a"), "category": "fuzz"}]}
        )


def test_public_seeded_corpus_executes_real_scanner_and_declared_tenant_contract():
    receipt = run_public_benchmark()
    assert receipt["scanner"] == "factoryline.review_audits.security_scan"
    assert receipt["decision"] == "PASS"
    assert receipt["metrics"]["stateful_invariant"]["tp"] == 1
    assert receipt["metrics"]["stateful_invariant"]["tn"] == 1
    assert receipt["metrics"]["tenant_isolation"]["tp"] == 1
    assert receipt["metrics"]["test_oracle_strength"]["tp"] == 3
    assert receipt["metrics"]["overall"]["tp"] == 6
    assert receipt["metrics"]["overall"]["fn"] == 0
    assert receipt["metrics"]["overall"]["recall"] == 1.0
    assert receipt["scanner_contract"]["tenant_read_calls"] == ["db.get"]
    assert receipt["scanner_contract"]["tenant_read_bindings"] == [
        "db.get=keyword:tenant_id:tenant_id"
    ]
    assert all(row["fixed_clean"] for row in receipt["cases"])
    assert receipt["metrics"]["tenant_isolation"]["fp"] == 0
    assert receipt["metrics"]["tenant_isolation"]["recall_ci95_wilson"] is not None
    assert receipt["measured_unsupported_behaviors"]["test_oracle_strength"] == {
        "state": "MEASURED",
        "positive_cases": 3,
        "true_positives": 3,
        "false_negatives": 0,
        "recall": 1.0,
        "recall_ci95_wilson": [0.438494, 1],
    }
    assert receipt["corpus_sha256"] and receipt["scanner_version"]
    assert len(receipt["source_bindings"]) == 16
    assert "not independently held out" in receipt["claim_boundary"]


def test_public_benchmark_hashes_and_parses_one_corpus_snapshot(tmp_path, monkeypatch):
    source = (
        Path(__file__).parents[1] / "factoryline" / "data" / "public_defect_corpus.json"
    )
    corpus = tmp_path / "corpus.json"
    snapshot = source.read_bytes()
    corpus.write_bytes(snapshot)
    real_read_bytes = Path.read_bytes
    reads = 0

    def read_then_replace(path: Path) -> bytes:
        nonlocal reads
        payload = real_read_bytes(path)
        if path.resolve() == corpus.resolve():
            reads += 1
            path.write_text(json.dumps({"cases": []}), encoding="utf-8")
        return payload

    monkeypatch.setattr(Path, "read_bytes", read_then_replace)
    receipt = run_public_benchmark(corpus)

    assert reads == 1
    assert receipt["corpus_sha256"] == hashlib.sha256(snapshot).hexdigest()
    assert receipt["metrics"]["overall"]["tp"] == 6
