import hashlib
import pytest

from factoryline.benchmark_lab import BenchmarkError, CLEAN_FINDING, SCHEMA, evaluate_benchmark, validate_benchmark_manifest


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _case(case_id: str, *, clean: bool = False, category: str = "stateful_invariant"):
    return {"id": case_id, "category": category, "source": f"fixtures/{case_id}", "source_sha256": _digest("a" + case_id[0]), "expected_finding": CLEAN_FINDING if clean else "refund-over-capture", "replay_argv": ["python", "-m", "pytest", f"tests/{case_id}.py"], "buggy_sha256": _digest("b" + case_id[0]), "fixed_sha256": _digest("c" + case_id[0])}


def test_benchmark_passes_real_defect_and_clean_control_with_metrics():
    manifest = {"schema": SCHEMA, "benchmark_id": "senior-fixtures", "version": "1", "cases": [_case("refund"), _case("clean", clean=True, category="tenant_isolation")]}
    observations = {"refund": {"buggy": {"state": "FAIL", "finding": "refund-over-capture"}, "fixed": {"state": "PASS", "finding": ""}}, "clean": {"buggy": {"state": "PASS", "finding": ""}, "fixed": {"state": "PASS", "finding": ""}}}
    receipt = evaluate_benchmark(manifest, observations)
    assert receipt["decision"] == "PASS"
    assert receipt["metrics"]["stateful_invariant"]["recall"] == 1.0
    assert receipt["metrics"]["tenant_isolation"]["tn"] == 1
    assert receipt["authority"] == "none"


def test_wrong_finding_blocks_with_replay_data():
    manifest = {"schema": SCHEMA, "benchmark_id": "senior-fixtures", "version": "1", "cases": [_case("refund")]}
    observations = {"refund": {"buggy": {"state": "PASS", "finding": ""}, "fixed": {"state": "PASS", "finding": ""}}}
    receipt = evaluate_benchmark(manifest, observations)
    assert receipt["decision"] == "BLOCKED"
    assert receipt["cases"][0]["replay_argv"][0] == "python"
    assert receipt["metrics"]["stateful_invariant"]["fn"] == 1


def test_manifest_rejects_urls_duplicates_and_unknown_category():
    base = {"schema": SCHEMA, "benchmark_id": "x", "version": "1", "cases": [_case("a")]}
    bad_url = {**base, "cases": [{**_case("a"), "source": "https://example.test/bug"}]}
    with pytest.raises(BenchmarkError, match="E_BENCHMARK_SOURCE"):
        validate_benchmark_manifest(bad_url)
    with pytest.raises(BenchmarkError, match="duplicate case"):
        validate_benchmark_manifest({**base, "cases": [_case("a"), _case("a")]})
    with pytest.raises(BenchmarkError, match="E_BENCHMARK_CATEGORY"):
        validate_benchmark_manifest({**base, "cases": [{**_case("a"), "category": "fuzz"}]})
