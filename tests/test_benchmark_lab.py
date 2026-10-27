import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from factoryline.benchmark_lab import (
    BenchmarkError,
    CLEAN_FINDING,
    SCHEMA,
    evaluate_benchmark,
    validate_benchmark_manifest,
    run_public_benchmark,
)
from factoryline.context_efficiency import (
    EXPERIMENT_SCHEMA,
    context_efficiency_status,
    evaluate_context_experiment,
    record_context_experiment,
)

_gain = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts/verify_precision_gain.py")
)


def _precision_pair():
    cases = [
        {"id": key, "source_sha256": _digest(key), "label": label}
        for key, label in (("a", "TP"), ("b", "FP"), ("c", "UNCLEAR"))
    ]
    seal = _gain["digest"](
        json.dumps(cases, sort_keys=True, separators=(",", ":")).encode()
    )
    contract = {
        "schema": _gain["SCHEMA"],
        "scope": "fixed_panel",
        "policy": "same",
        "context_sha256": _digest("context"),
        "assumptions_sha256": _digest("profile"),
        "labels_sha256": seal,
        "cases": cases,
        "expected_changes": {},
    }
    version = {
        key: contract[key]
        for key in ("policy", "context_sha256", "assumptions_sha256", "labels_sha256")
    }
    version.update(
        scanner_sha256=_digest("scanner"),
        unlabelled_outputs=0,
        cases=[
            dict(
                row,
                raw=True,
                active=True,
                review=False,
                supported=False,
                scan_complete=True,
            )
            for row in cases
        ],
    )
    return contract, version, copy.deepcopy(version)


def test_precision_gate_recomputes_and_rejects_unchanged_aggregate_claim():
    contract, before, after = _precision_pair()
    after["precision"] = 1.0
    result = _gain["evaluate"](contract, before, after)
    assert result["state"] == "NO_PRECISION_GAIN"
    assert result["metrics"]["candidate"]["active"]["precision"] == 0.5
    assert result["metrics"]["candidate"]["active"]["unclear_inclusive_rate"] == 1 / 3


def test_precision_gate_requires_registered_delta_and_keeps_abstentions_visible():
    contract, before, after = _precision_pair()
    after["cases"][1].update(active=False, review=True)
    assert _gain["evaluate"](contract, before, after)["state"] == "BLOCKED"
    contract["expected_changes"] = {
        "b": {"before": ["raw", "active"], "after": ["raw", "review"]}
    }
    result = _gain["evaluate"](contract, before, after)
    assert result["state"] == "ACTIVE_PRECISION_GAIN_FIXED_PANEL"
    assert result["change_kind"] == "SELECTION_WITH_ABSTENTION"
    assert result["metrics"]["candidate"]["active_or_review"]["precision"] == 0.5
    assert result["metrics"]["candidate"]["review"]["FP"] == 1
    assert result["metrics"]["candidate"]["raw"]["FP"] == 1
    assert result["publication_eligible"] is False
    after["unlabelled_outputs"] = 75
    assert (
        _gain["evaluate"](contract, before, after)["unlabelled_outputs"]["candidate"]
        == 75
    )


@pytest.mark.parametrize(
    "change",
    [
        "source",
        "label",
        "context",
        "policy",
        "assumptions",
        "missing",
        "duplicate",
        "boolean",
        "derived",
        "empty",
    ],
)
def test_precision_gate_rejects_incomparable_or_malformed_observations(change):
    contract, before, after = _precision_pair()
    if change == "source":
        after["cases"][0]["source_sha256"] = _digest("different")
    elif change == "label":
        after["cases"][0]["label"] = "FP"
    elif change in {"context", "policy", "assumptions"}:
        after[change + ("_sha256" if change != "policy" else "")] = "changed"
    elif change == "missing":
        after["cases"].pop()
    elif change == "duplicate":
        after["cases"].append(after["cases"][0])
    elif change == "boolean":
        after["cases"][0]["active"] = 1
    elif change == "derived":
        after["cases"][0]["raw"] = False
    else:
        contract["cases"] = []
    with pytest.raises(ValueError):
        _gain["evaluate"](contract, before, after)


@pytest.mark.parametrize("change", ["timeout", "lost_tp", "stronger_proof"])
def test_precision_gate_distinguishes_blockers_from_evidence_strength(change):
    contract, before, after = _precision_pair()
    if change == "timeout":
        after["cases"][0]["scan_complete"] = False
    elif change == "lost_tp":
        after["cases"][0].update(active=False, review=True)
        contract["expected_changes"] = {
            "a": {"before": ["raw", "active"], "after": ["raw", "review"]}
        }
    else:
        after["cases"][0]["supported"] = True
        contract["expected_changes"] = {
            "a": {"before": ["raw", "active"], "after": ["raw", "active", "supported"]}
        }
    result = _gain["evaluate"](contract, before, after)
    assert result["state"] == (
        "NO_PRECISION_GAIN" if change == "stronger_proof" else "BLOCKED"
    )


def test_precision_bound_reader_rejects_stale_and_escaping_artifact(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text("{}")
    reference = {"path": path.name, "sha256": _gain["digest"](b"{}")}
    assert _gain["_read_bound"](tmp_path, reference) == {}
    path.write_text('{"changed": true}')
    with pytest.raises(ValueError, match="digest mismatch"):
        _gain["_read_bound"](tmp_path, reference)
    with pytest.raises(ValueError, match="escapes"):
        _gain["_read_bound"](
            tmp_path, {"path": "../elsewhere", "sha256": reference["sha256"]}
        )


@pytest.mark.parametrize(
    "payload",
    [[], {"schema": _gain["SCHEMA"], "scope": "fixed_panel", "cases": [None]}],
)
def test_precision_gate_rejects_invalid_document_shape(payload):
    with pytest.raises(ValueError):
        _gain["evaluate"](payload, {}, {})


@pytest.mark.parametrize("valid", [True, False])
def test_precision_cli_writes_receipt_for_no_gain_and_invalid_json(tmp_path, valid):
    contract, before, after = _precision_pair()
    for name, value in (("baseline", before), ("candidate", after)):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(value))
        contract[name] = {
            "path": path.name,
            "sha256": _gain["digest"](path.read_bytes()),
        }
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(contract) if valid else "{broken")
    output = tmp_path / "result.json"
    script = Path(__file__).resolve().parents[1] / "scripts/verify_precision_gain.py"
    result = subprocess.run(
        [sys.executable, str(script), str(path), "--out", str(output)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 2
    assert json.loads(output.read_text())["state"] == (
        "NO_PRECISION_GAIN" if valid else "INVALID"
    )


@pytest.mark.parametrize("label", ["TP", "UNCLEAR"])
def test_precision_gate_blocks_lost_reviewed_claim_even_when_active_precision_rises(
    label,
):
    contract, before, after = _precision_pair()
    key = "a" if label == "TP" else "c"
    index = 0 if label == "TP" else 2
    before["cases"][index].update(active=False, review=True)
    after["cases"][index].update(active=False, review=False)
    after["cases"][1].update(active=False, review=True)
    contract["expected_changes"] = {
        key: {"before": ["raw", "review"], "after": ["raw"]},
        "b": {"before": ["raw", "active"], "after": ["raw", "review"]},
    }
    assert _gain["evaluate"](contract, before, after)["state"] == "BLOCKED"


def test_precision_gate_rejects_supported_defect_outside_active_population():
    contract, before, after = _precision_pair()
    after["cases"][0].update(active=False, review=True, supported=True)
    with pytest.raises(ValueError, match="supported defect must be active"):
        _gain["evaluate"](contract, before, after)


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


def test_versioned_seeded_corpus_keeps_unresolved_calls_in_unknown_tier(tmp_path):
    from factoryline.review_audits import security_scan

    corpus_path = (
        Path(__file__).parents[1] / "factoryline/data/public_defect_corpus.json"
    )
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    assert corpus["version"] == "2"
    assert corpus["changes_from_version_1"]
    source = tmp_path / "test_control.py"
    for case in corpus["unknown_controls"]:
        source.write_text(case["source"], encoding="utf-8")
        result = security_scan(tmp_path, cache_enabled=False)
        assert result["finding_counts"] == {case["expected_finding"]: 1}
        assert result["findings"][0]["severity"] == "INFO"
        assert result["state"] == "INCOMPLETE"


def _paired_context_observation():
    return {
        "schema": EXPERIMENT_SCHEMA,
        "task_sha256": _digest("task"),
        "revision_sha256": _digest("revision"),
        "model_id": "operator-recorded-model",
        "tools_sha256": _digest("tools"),
        "budget_sha256": _digest("budgets"),
        "rubric_sha256": _digest("rubric"),
        "cost_unit": "USD",
        "evidence_level": "operator_supplied_unverified",
        "samples": [
            {
                "id": f"pair-{index}",
                "baseline": {
                    "phases_seconds": {
                        "context_gathering": 1,
                        "coding": 7,
                        "repair": 2,
                    },
                    "quality": 90,
                    "cost": 1.0,
                    "tokens": 1000,
                },
                "context": {
                    "phases_seconds": {
                        "context_gathering": 1,
                        "coding": 2,
                        "repair": 1,
                    },
                    "quality": 90,
                    "cost": 0.8,
                    "tokens": 800,
                },
            }
            for index in range(3)
        ],
    }


def test_context_engine_pair_counts_all_phases_and_ui_is_explicitly_unverified(
    tmp_path,
):
    observed = _paired_context_observation()
    result = evaluate_context_experiment(observed)
    assert result["state"] == "TARGET_MET"
    assert result["observed_latency_reduction"] == pytest.approx(0.6)
    assert result["observed_cost_delta"] == pytest.approx(-0.2)
    assert result["observed_cost_delta_unit"] == "USD"
    assert result["observed_token_delta"] == pytest.approx(-200)
    assert result["observed_token_delta_unit"] == "tokens"
    assert result["evidence_level"] == "operator_supplied_unverified"
    assert record_context_experiment(tmp_path, observed)["state"] == "TARGET_MET"
    status = context_efficiency_status(tmp_path)
    assert status["paired_sample_count"] == 3
    assert status["experiment_status"] == "TARGET_MET"
    assert status["experiment_freshness"] == "UNVERIFIED"
    assert status["observed_latency_reduction"] == pytest.approx(0.6)


def test_context_engine_pair_rejects_incomplete_or_tampered_evidence(tmp_path):
    malformed = _paired_context_observation()
    del malformed["samples"][0]["context"]["phases_seconds"]["repair"]
    with pytest.raises(ValueError, match="E_EXPERIMENT_PHASES"):
        evaluate_context_experiment(malformed)
    unpaired = _paired_context_observation()
    del unpaired["samples"][0]["context"]["cost"]
    with pytest.raises(ValueError, match="E_EXPERIMENT_METRIC"):
        evaluate_context_experiment(unpaired)
    record_context_experiment(tmp_path, _paired_context_observation())
    path = tmp_path / ".factory" / "context-efficiency" / "experiment.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored["results"][-1]["result"]["observed_latency_reduction"] = 0.99
    path.write_text(json.dumps(stored), encoding="utf-8")
    assert context_efficiency_status(tmp_path)["experiment_status"] == "BLOCKED"


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


# Optional reproducible paired performance runner.
# Invoke: python tests/test_benchmark_lab.py --prestige-root <checkout>


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        default=lambda item: item.__dict__,
    )


def _measure(operation: Callable[[], Any], runs: int = 11) -> dict[str, Any]:
    expected = _canonical(operation())
    samples = []
    for _ in range(runs):
        start = time.perf_counter_ns()
        result = operation()
        samples.append((time.perf_counter_ns() - start) / 1_000_000)
        if _canonical(result) != expected:
            raise RuntimeError("deterministic output parity failed")
    return {
        "median_ms": round(statistics.median(samples), 3),
        "min_ms": round(min(samples), 3),
        "max_ms": round(max(samples), 3),
        "runs": runs,
        "output_parity": True,
        "output_sha256": hashlib.sha256(expected.encode("utf-8")).hexdigest(),
    }


def _old_json_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _old_text_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Paired repeat-run benchmark for Code Factory and Prestige optimizations."
    )
    parser.add_argument(
        "--prestige-root", type=Path, required=True, help="Prestige checkout path"
    )
    parser.add_argument("--runs", type=int, default=11)
    args = parser.parse_args()
    if args.runs < 3:
        parser.error("--runs must be at least 3")

    cf_root = Path.cwd().resolve()
    prestige_root = args.prestige_root.resolve()
    sys.path.insert(0, str(cf_root))
    sys.path.insert(0, str(prestige_root))

    import factoryline.appforge_design as appforge_module
    import factoryline.revenue_evidence as evidence_module
    import factoryline.revenueforge as revenueforge_module
    import prestige_design.purpose as purpose_module
    from factoryline.appforge_design import compile_appforge_design
    from factoryline.revenueforge import build_revenue_bundle
    from prestige_design.score import score_design

    brief = cf_root / "examples/revenueforge/appforge-design-brief.json"
    products = cf_root / "examples/revenueforge/products.yaml"
    appforge_output = Path(".factory/perf-benchmark/appforge")
    revenueforge_output = Path(".factory/perf-benchmark/revenueforge")
    compile_appforge_design(cf_root, brief, appforge_output)
    build_revenue_bundle(cf_root, products, revenueforge_output)

    original_writes = (
        evidence_module._atomic_json,
        appforge_module._atomic_json,
        revenueforge_module._atomic,
        Path.is_file,
    )
    original_is_file = Path.is_file

    def old_skill_probe(path: Path) -> bool:
        return (
            False
            if path.name == "APPFORGE_DESIGN_DIRECTOR.md"
            else original_is_file(path)
        )

    try:
        evidence_module._atomic_json = _old_json_write
        appforge_module._atomic_json = _old_json_write
        revenueforge_module._atomic = _old_text_write
        Path.is_file = old_skill_probe
        appforge_baseline = _measure(
            lambda: compile_appforge_design(cf_root, brief, appforge_output), args.runs
        )
        revenueforge_baseline = _measure(
            lambda: build_revenue_bundle(cf_root, products, revenueforge_output),
            args.runs,
        )
    finally:
        (
            evidence_module._atomic_json,
            appforge_module._atomic_json,
            revenueforge_module._atomic,
            Path.is_file,
        ) = original_writes

    appforge_candidate = _measure(
        lambda: compile_appforge_design(cf_root, brief, appforge_output), args.runs
    )
    revenueforge_candidate = _measure(
        lambda: build_revenue_bundle(cf_root, products, revenueforge_output), args.runs
    )

    html = (cf_root / "factoryline/graph_ops.html").read_text(encoding="utf-8")
    original_counter = purpose_module._count_terms

    def regex_reference(text: str, terms: tuple[str, ...]) -> int:
        return sum(
            1 for term in terms if re.search(rf"\b{re.escape(term.lower())}\b", text)
        )

    def score_with(counter: Callable[..., int]) -> dict[str, Any]:
        purpose_module._count_terms = counter
        try:
            return _measure(
                lambda: score_design(
                    html, workflow_key="product", purpose_key="developer"
                ),
                args.runs,
            )
        finally:
            purpose_module._count_terms = original_counter

    prestige_baseline = score_with(regex_reference)
    prestige_candidate = score_with(original_counter)
    for name, baseline, candidate in (
        ("AppForge", appforge_baseline, appforge_candidate),
        ("RevenueForge", revenueforge_baseline, revenueforge_candidate),
        ("Prestige", prestige_baseline, prestige_candidate),
    ):
        if baseline["output_sha256"] != candidate["output_sha256"]:
            raise RuntimeError(f"{name} baseline and candidate outputs differ")
    result = {
        "runtime": sys.version,
        "method": "paired same-process 11-run medians; exact serialized output parity",
        "baseline_definition": "Legacy unconditional atomic replacements for AppForge and RevenueForge, and the prior Python regex word-boundary matcher for Prestige.",
        "input": {
            "appforge": brief.relative_to(cf_root).as_posix(),
            "revenueforge": products.relative_to(cf_root).as_posix(),
            "prestige_html": "factoryline/graph_ops.html",
            "prestige_checkout": str(prestige_root),
        },
        "baseline": {
            "appforge": appforge_baseline,
            "revenueforge": revenueforge_baseline,
            "prestige_score": prestige_baseline,
        },
        "candidate": {
            "appforge": appforge_candidate,
            "revenueforge": revenueforge_candidate,
            "prestige_score": prestige_candidate,
        },
        "median_change_percent": {
            key: round(
                (candidate["median_ms"] / baseline["median_ms"] - 1) * 100,
                1,
            )
            for key, baseline, candidate in (
                ("appforge", appforge_baseline, appforge_candidate),
                ("revenueforge", revenueforge_baseline, revenueforge_candidate),
                ("prestige_score", prestige_baseline, prestige_candidate),
            )
        },
    }
    result_path = cf_root / ".factory/perf-benchmark/results.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
