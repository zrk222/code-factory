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

from factoryline.senior_assurance import evaluate_source_bound_recall

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
    assert result["metrics"]["candidate"]["active"]["precision_label_bounds"] == [
        1 / 3,
        2 / 3,
    ]


def test_development_precision_gate_requires_raw_gain_and_completed_scans():
    contract, before, after = _precision_pair()
    evaluate = _gain["evaluate"]
    assert (
        evaluate(contract, before, after, development_gate=True)["state"] == "BLOCKED"
    )
    after["cases"][1].update(raw=False, active=False)
    contract["expected_changes"] = {"b": {"before": ["raw", "active"], "after": []}}
    passed = evaluate(contract, before, after, development_gate=True)
    assert passed["state"] == "DEVELOPMENT_GATE_PASS"
    assert passed["metrics"]["candidate"]["supported"]["precision"] is None
    after["cases"][0]["scan_complete"] = False
    assert (
        evaluate(contract, before, after, development_gate=True)["state"] == "BLOCKED"
    )


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
    blocked = _gain["evaluate"](contract, before, after)
    assert blocked["state"] == "BLOCKED"
    assert blocked["unlabelled_outputs"]["candidate"] == 75
    assert blocked["reasons"] == ["candidate: reconcile 75 unlabelled outputs"]


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
def test_precision_cli_writes_receipt_and_operator_summary(tmp_path, valid):
    contract, before, after = _precision_pair()
    before["elapsed_seconds"] = 4
    after["elapsed_seconds"] = 3.5
    after["cases"][0].update(active=False, review=True)
    contract["expected_changes"] = {
        "a": {"before": ["raw", "active"], "after": ["raw", "review"]}
    }
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
        [sys.executable, str(script), str(path), "--out", str(output), "--summary"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 2
    receipt = json.loads(output.read_text())
    assert receipt["state"] == ("BLOCKED" if valid else "INVALID")
    if valid:
        assert "Known TP losses: a" in result.stdout
        assert "1 known TPs outside active, 1 for review" in result.stdout
        assert "Recorded runtime: 4.00s -> 3.50s" in result.stdout
        assert receipt["elapsed_seconds"]["delta"] == -0.5
        assert receipt["contract_sha256"] == _gain["digest"](path.read_bytes())
        assert receipt["evidence"] == {
            name: contract[name] for name in ("baseline", "candidate")
        }
    else:
        assert result.stdout.startswith("INVALID")


def test_precision_cli_cannot_overwrite_bound_observation(tmp_path, capsys):
    contract, before, _after = _precision_pair()
    observation = tmp_path / "baseline.json"
    payload = json.dumps(before).encode()
    observation.write_bytes(payload)
    contract["baseline"] = {
        "path": observation.name,
        "sha256": _gain["digest"](payload),
    }
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(contract))
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sys, "argv", ["verify", str(path), "--out", str(observation)])
        with pytest.raises(SystemExit, match="2"):
            _gain["main"]()
    assert "must not replace an observation" in capsys.readouterr().err
    assert observation.read_bytes() == payload


def _single_arm_precision_panel(admission=False):
    scope = {
        key: _digest(key)
        for key in ("scanner_sha256", "registration_sha256", "configuration_sha256")
    }
    contract = {"schema": _gain["SINGLE_ARM_SCHEMA"], **scope, "sample_target": 3}
    selection = {
        **scope,
        "collection": {"registered": 2, "complete": 2},
        "observed_raw": 5,
        "sample_target": 3,
        "admission_available": admission,
        "cases": [
            {
                "id": key,
                "source_sha256": _digest(key + " source"),
                "packet_sha256": _digest(key + " packet"),
                "report_sha256": _digest("normal report"),
                "finding_sha256": _digest(key + " finding"),
                "admitted": key != "c" if admission else None,
            }
            for key in "abc"
        ],
    }
    reviews = [
        {
            "reviewer_id": reviewer,
            "cases": [
                {
                    **{
                        key: row[key]
                        for key in ("id", "source_sha256", "packet_sha256")
                    },
                    "label": label,
                }
                for row, label in zip(selection["cases"], labels)
            ],
        }
        for reviewer, labels in (
            ("one", ("TP", "FP", "FP")),
            ("two", ("TP", "TP", "FP")),
        )
    ]
    _seal_single_arm_selection(contract, selection, reviews)
    return contract, selection, reviews


def _seal_single_arm_selection(contract, selection, reviews):
    seal = _gain["digest"](_gain["canonical_bytes"](selection))
    contract["selection_sha256"] = seal
    for review in reviews:
        review["selection_sha256"] = seal


@pytest.mark.parametrize("admission", [False, True])
def test_single_arm_precision_uses_only_decided_raw_alerts(admission):
    contract, selection, reviews = _single_arm_precision_panel(admission)
    result = _gain["evaluate_single_arm"](contract, selection, reviews)
    raw = result["metrics"]["raw"]
    assert result["state"] == "SCORED_SINGLE_ARM"
    assert result["consensus"] == {"a": "TP", "b": "UNCLEAR", "c": "FP"}
    assert result["disagreements"] == ["b"]
    assert (raw["TP"], raw["FP"], raw["UNCLEAR"]) == (1, 1, 1)
    assert (raw["emitted"], raw["decided"], raw["precision"]) == (3, 2, 0.5)
    assert raw["precision_label_bounds"] == pytest.approx([1 / 3, 2 / 3])
    assert (result["observed_raw"], result["unselected_raw"]) == (5, 2)
    assert result["publication_eligible"] is False
    admitted = result["metrics"]["admitted"]
    if admission:
        assert (admitted["emitted"], admitted["decided"], admitted["precision"]) == (
            2,
            1,
            1,
        )
    else:
        assert admitted is None


def test_single_arm_keeps_failed_captures_and_remaining_selection_visible():
    contract, selection, reviews = _single_arm_precision_panel()
    selection["collection"]["complete"] = 1
    contract["sample_target"] = selection["sample_target"] = 4
    _seal_single_arm_selection(contract, selection, reviews)
    result = _gain["evaluate_single_arm"](contract, selection, reviews)
    assert result["state"] == "INCOMPLETE"
    assert result["collection"] == {"registered": 2, "complete": 1, "unobserved": 1}
    assert (result["sample_target"], result["selected_raw"]) == (4, 3)
    assert result["metrics"]["raw"]["decided"] == 2
    assert result["metrics"]["admitted"] is None


def test_single_arm_zero_observed_alerts_have_no_precision():
    contract, selection, reviews = _single_arm_precision_panel(admission=True)
    selection.update(observed_raw=0, cases=[])
    for review in reviews:
        review["cases"] = []
    _seal_single_arm_selection(contract, selection, reviews)
    result = _gain["evaluate_single_arm"](contract, selection, reviews)
    assert result["state"] == "INCOMPLETE"
    for metrics in result["metrics"].values():
        assert metrics["emitted"] == metrics["decided"] == 0
        assert metrics["precision"] is None
        assert metrics["precision_label_bounds"] is None


def test_single_arm_rejects_double_weighting_a_raw_observation():
    contract, selection, reviews = _single_arm_precision_panel()
    first, duplicate = selection["cases"][:2]
    for field in ("finding_sha256", "report_sha256", "source_sha256"):
        duplicate[field] = first[field]
    for review in reviews:
        review["cases"][1]["source_sha256"] = first["source_sha256"]
    _seal_single_arm_selection(contract, selection, reviews)
    with pytest.raises(ValueError, match="repeat one raw observation"):
        _gain["evaluate_single_arm"](contract, selection, reviews)


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("selection", "selection seal"),
        ("configuration", "frozen candidate"),
        ("duplicate_reviewer", "distinct reviewer"),
        ("missing_packet", "omitted or added"),
        ("packet_binding", "reviewer source/packet"),
        ("admission", "contradicts availability"),
        ("denominator", "selection denominator"),
        ("target", "sample target differs"),
    ],
)
def test_single_arm_precision_rejects_drift(mutation, reason):
    contract, selection, reviews = _single_arm_precision_panel()
    if mutation == "selection":
        selection["observed_raw"] += 1
    elif mutation == "configuration":
        selection["configuration_sha256"] = _digest("changed profile")
    elif mutation == "duplicate_reviewer":
        reviews[1]["reviewer_id"] = reviews[0]["reviewer_id"].upper()
    elif mutation == "missing_packet":
        reviews[1]["cases"].pop()
    elif mutation == "packet_binding":
        reviews[1]["cases"][0]["packet_sha256"] = _digest("other packet")
    elif mutation == "admission":
        selection["cases"][0]["admitted"] = False
    elif mutation == "target":
        contract["sample_target"] += 1
    else:
        selection["observed_raw"] = 1
    if mutation != "selection":
        _seal_single_arm_selection(contract, selection, reviews)
    with pytest.raises(ValueError, match=reason):
        _gain["evaluate_single_arm"](contract, selection, reviews)


def test_single_arm_cli_seals_receipt_and_protects_reviewer_input(tmp_path):
    contract, selection, reviews = _single_arm_precision_panel()
    refs = []
    for name, value in zip(
        ("selection", "reviewer-one", "reviewer-two"), [selection, *reviews]
    ):
        path = tmp_path / (name + ".json")
        payload = _gain["canonical_bytes"](value)
        path.write_bytes(payload)
        refs.append({"path": path.name, "sha256": _gain["digest"](payload)})
    contract.update(selection=refs[0], reviewers=refs[1:])
    manifest = tmp_path / "contract.json"
    contract_bytes = _gain["canonical_bytes"](contract)
    manifest.write_bytes(contract_bytes)
    receipt = tmp_path / "receipt.json"
    script = Path(__file__).resolve().parents[1] / "scripts/verify_precision_gain.py"
    command = [sys.executable, str(script), str(manifest), "--out"]
    scored = subprocess.run(
        [*command, str(receipt), "--summary"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert scored.returncode == 0, scored.stderr
    assert "admitted: unavailable" in scored.stdout
    assert json.loads(receipt.read_bytes())["evidence"] == {
        "selection": refs[0],
        "reviewers": refs[1:],
    }
    reviewer = tmp_path / refs[1]["path"]
    before = reviewer.read_bytes()
    rejected = subprocess.run(
        [*command, str(reviewer)], capture_output=True, text=True, timeout=20
    )
    assert rejected.returncode == 2
    assert "must not replace an observation" in rejected.stderr
    assert reviewer.read_bytes() == before
    ambiguous_manifests = (
        b'{"sample_target": 3,' + contract_bytes[1:],
        contract_bytes.rstrip()[:-1]
        + b',"schema":"factory.precision-gain.v1","reviewers":[]}',
    )
    for ambiguous in ambiguous_manifests:
        manifest.write_bytes(ambiguous)
        rejected = subprocess.run(
            [*command, str(reviewer)], capture_output=True, text=True, timeout=20
        )
        assert rejected.returncode == 2
        assert "duplicate JSON key" in rejected.stderr
        assert reviewer.read_bytes() == before


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


def _recall_pair():
    """Entirely synthetic source bindings; no external corpus is consulted."""
    from factoryline.runtime_audit_common import canonical_bytes

    cases = []
    rows = {}
    for key, truth in (
        ("positive", "POSITIVE"),
        ("clean", "CLEAN"),
        ("unclear", "UNCLEAR"),
    ):
        path = f"synthetic/{key}.py"
        source_hash = _digest(f"synthetic source {key}")
        cases.append(
            {
                "id": key,
                "category": "stateful_invariant",
                "path": path,
                "source_sha256": source_hash,
                "truth": truth,
                "expected": {"rule": "synthetic-rule", "line": 3}
                if truth == "POSITIVE"
                else None,
            }
        )
        finding = [{"rule": "synthetic-rule", "line": 3}] if truth == "POSITIVE" else []
        rows[key] = {
            "path": path,
            "source_sha256": source_hash,
            "report_sha256": _digest(f"synthetic report {key}"),
            "raw": finding,
            "admitted": copy.deepcopy(finding),
        }
    observations = {
        "schema": "factory.defect-recall-observations.v1",
        "scanner_sha256": _digest("scanner"),
        "configuration_sha256": _digest("configuration"),
        "cases": rows,
    }
    manifest = {
        "schema": "factory.defect-recall.v1",
        "benchmark_id": "synthetic-recall",
        "version": "1",
        "partition": "public",
        "scanner_sha256": observations["scanner_sha256"],
        "configuration_sha256": observations["configuration_sha256"],
        "observations_sha256": hashlib.sha256(
            canonical_bytes(observations)
        ).hexdigest(),
        "cases": cases,
    }
    return manifest, observations


def _seal_recall(manifest, observations):
    from factoryline.runtime_audit_common import canonical_bytes

    manifest["observations_sha256"] = hashlib.sha256(
        canonical_bytes(observations)
    ).hexdigest()


def test_source_bound_recall_keeps_admission_denominator_and_deduplicates():
    manifest, observations = _recall_pair()
    observations["cases"]["positive"]["raw"] *= 2
    observations["cases"]["positive"]["admitted"] = []
    _seal_recall(manifest, observations)
    result = evaluate_source_bound_recall(manifest, observations)
    metric = result["metrics"]["overall"]
    assert result["decision"] == "MEASURED"
    assert metric["known_positives"] == 1
    assert metric["unclear_truth"] == 1
    assert metric["raw"]["denominator"] == metric["admitted"]["denominator"] == 1
    assert metric["raw"]["detected"] == 1
    assert metric["raw"]["recall"] == 1.0
    assert metric["admitted"]["false_negatives"] == 1
    assert metric["admitted"]["recall"] == 0.0
    assert metric["raw"]["clean_controls"] == {
        "denominator": 1,
        "flagged": 0,
        "clean": 1,
        "unobserved": 0,
    }
    assert result["metrics"]["by_category"]["stateful_invariant"] == metric


def test_source_bound_recall_preserves_unobserved_and_bounds():
    manifest, observations = _recall_pair()
    del observations["cases"]["positive"]
    _seal_recall(manifest, observations)
    result = evaluate_source_bound_recall(manifest, observations)
    assert result["decision"] == "INCOMPLETE"
    for arm in ("raw", "admitted"):
        metric = result["metrics"]["overall"][arm]
        assert metric["denominator"] == 1
        assert metric["unobserved"] == 1
        assert metric["false_negatives"] == 0
        assert metric["recall"] is None
        assert metric["recall_lower_bound"] == 0.0
        assert metric["recall_upper_bound"] == 1.0
        assert metric["recall_ci95_wilson"] is None


def test_source_bound_recall_absent_admission_and_wrong_site():
    manifest, observations = _recall_pair()
    observations["cases"]["positive"].update(
        raw=[{"rule": "synthetic-rule", "line": 4}],
        admitted=None,
    )
    _seal_recall(manifest, observations)
    result = evaluate_source_bound_recall(manifest, observations)
    metric = result["metrics"]["overall"]
    assert result["decision"] == "INCOMPLETE"
    assert metric["raw"]["false_negatives"] == 1
    assert metric["raw"]["recall"] == 0.0
    assert metric["admitted"]["recall"] is None
    assert metric["admitted"]["unobserved"] == 1


@pytest.mark.parametrize("conflict", ["raw", "admitted"])
def test_source_bound_recall_rejects_conflicting_populations_for_one_report(conflict):
    manifest, observations = _recall_pair()
    positive = manifest["cases"][0]
    manifest["cases"].append(
        {
            **positive,
            "id": "second",
            "expected": {"rule": "synthetic-rule", "line": 4},
        }
    )
    capture = observations["cases"]["positive"]
    capture["raw"].append({"rule": "synthetic-rule", "line": 4})
    capture["admitted"] = copy.deepcopy(capture["raw"])
    observations["cases"]["second"] = copy.deepcopy(capture)
    observations["cases"]["second"][conflict] = None
    if conflict == "raw":
        observations["cases"]["second"]["admitted"] = None
    _seal_recall(manifest, observations)
    with pytest.raises(BenchmarkError, match="Conflicting populations"):
        evaluate_source_bound_recall(manifest, observations)
    observations["cases"]["second"] = copy.deepcopy(capture)
    _seal_recall(manifest, observations)
    result = evaluate_source_bound_recall(manifest, observations)
    assert result["metrics"]["overall"]["raw"]["detected"] == 2


@pytest.mark.parametrize("existing", [0, 1])
def test_source_bound_recall_rejects_reused_clean_control_scope(existing):
    manifest, observations = _recall_pair()
    manifest["cases"].append(
        {
            **manifest["cases"][existing],
            "id": "second",
            "truth": "CLEAN",
            "expected": None,
        }
    )
    with pytest.raises(
        BenchmarkError, match="Duplicate or contradictory clean control"
    ):
        evaluate_source_bound_recall(manifest, observations)


def test_source_bound_recall_requires_consistent_report_and_source_identity():
    manifest, observations = _recall_pair()
    positive = manifest["cases"][0]
    capture = observations["cases"]["positive"]
    second = {**positive, "id": "second", "expected": {"rule": "other", "line": 4}}
    second_capture = copy.deepcopy(capture)
    manifest["cases"].append(second)
    observations["cases"]["second"] = second_capture

    second_capture["report_sha256"] = _digest("alternate report for the same source")
    _seal_recall(manifest, observations)
    with pytest.raises(BenchmarkError, match="Conflicting populations or reports"):
        evaluate_source_bound_recall(manifest, observations)

    second["source_sha256"] = second_capture["source_sha256"] = _digest("variant")
    _seal_recall(manifest, observations)
    result = evaluate_source_bound_recall(manifest, observations)
    assert result["metrics"]["overall"]["raw"]["denominator"] == 2

    second_capture["report_sha256"] = capture["report_sha256"]
    _seal_recall(manifest, observations)
    with pytest.raises(BenchmarkError, match="multiple source digests for one path"):
        evaluate_source_bound_recall(manifest, observations)


@pytest.mark.parametrize(
    "mutation",
    ["seal", "scanner", "configuration", "source", "path", "extra", "subset"],
)
def test_source_bound_recall_rejects_drift_and_invalid_observations(mutation):
    manifest, observations = _recall_pair()
    if mutation == "seal":
        manifest["observations_sha256"] = _digest("incorrect seal")
    elif mutation in {"scanner", "configuration"}:
        observations[f"{mutation}_sha256"] = _digest("drift")
    elif mutation == "source":
        observations["cases"]["positive"]["source_sha256"] = _digest("drift")
    elif mutation == "path":
        observations["cases"]["positive"]["path"] = "synthetic/other.py"
    elif mutation == "extra":
        observations["cases"]["extra"] = copy.deepcopy(
            observations["cases"]["positive"]
        )
    else:
        observations["cases"]["positive"]["admitted"] = [{"rule": "other", "line": 3}]
    if mutation != "seal":
        _seal_recall(manifest, observations)
    with pytest.raises(BenchmarkError):
        evaluate_source_bound_recall(manifest, observations)


def test_source_bound_recall_zero_positive_is_not_measured():
    manifest, observations = _recall_pair()
    manifest["cases"] = manifest["cases"][1:]
    del observations["cases"]["positive"]
    _seal_recall(manifest, observations)
    result = evaluate_source_bound_recall(manifest, observations)
    assert result["decision"] == "INCOMPLETE"
    for arm in ("raw", "admitted"):
        metric = result["metrics"]["overall"][arm]
        assert metric["denominator"] == 0
        assert metric["recall"] is None
        assert metric["recall_ci95_wilson"] is None


def test_source_bound_recall_keeps_measured_misses_and_missing_captures_separate():
    manifest, observations = _recall_pair()
    positive = manifest["cases"][0]
    capture = observations["cases"]["positive"]
    for key in ("observed-miss", "unobserved"):
        path, source = f"synthetic/{key}.py", _digest(key)
        manifest["cases"].append(
            {**positive, "id": key, "path": path, "source_sha256": source}
        )
        if key == "observed-miss":
            observations["cases"][key] = {
                **capture,
                "path": path,
                "source_sha256": source,
                "report_sha256": _digest("empty report"),
                "raw": [],
                "admitted": [],
            }
    _seal_recall(manifest, observations)
    metrics = evaluate_source_bound_recall(manifest, observations)["metrics"]["overall"]
    for arm in ("raw", "admitted"):
        row = metrics[arm]
        assert row["denominator"] == 3
        assert (row["detected"], row["false_negatives"], row["unobserved"]) == (1, 1, 1)
        assert row["recall"] is None
        assert row["recall_lower_bound"] == pytest.approx(1 / 3)
        assert row["recall_upper_bound"] == pytest.approx(2 / 3)


@pytest.mark.parametrize("missing,expected_exit", [(False, 0), (True, 1)])
def test_senior_benchmark_routes_source_bound_recall(
    tmp_path, capsys, missing, expected_exit
):
    from factoryline.cli import main

    manifest, observations = _recall_pair()
    if missing:
        del observations["cases"]["positive"]
        _seal_recall(manifest, observations)
    contract_path = tmp_path / "manifest.json"
    capture_path = tmp_path / "capture.json"
    output_path = tmp_path / "receipt.json"
    contract_path.write_text(json.dumps(manifest), encoding="utf-8")
    capture_path.write_text(json.dumps(observations), encoding="utf-8")
    assert (
        main(
            [
                "senior",
                "benchmark",
                str(contract_path),
                "--observations",
                str(capture_path),
                "--out",
                str(output_path),
                "--json",
            ]
        )
        == expected_exit
    )
    receipt = json.loads(output_path.read_bytes())
    assert receipt["schema"] == "factory.defect-recall-receipt.v1"
    assert receipt["authority"] == "none" and receipt["release_approval"] is False
    assert json.loads(capsys.readouterr().out)["decision"] == receipt["decision"]


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

_ROOT = Path(__file__).resolve().parents[1]
_RECALL_RECORD = _ROOT / "docs/evidence/advisory-recall-factory-20261121.json"


@pytest.fixture(scope="module")
def recall_record():
    return json.loads(_RECALL_RECORD.read_text(encoding="utf-8"))


def test_advisory_recall_record_recomputes_lane_separated_summary(recall_record):
    summary = _gain["verify_recall"](recall_record)
    assert summary["total"] == {
        "cases": 161,
        "pattern_detected": 6,
        "codeql_detected": 15,
        "combined_detected": 20,
        "overlap": 1,
        "codeql_analyzed": 91,
        "codeql_state_extraction_failed": 10,
        "codeql_state_no_class_query": 2,
        "codeql_state_not_run": 33,
        "codeql_state_no_extractor": 25,
    }
    assert summary["codeql_untuned"]["wilson_95_over_analyzed"] == [0.102513, 0.254309]
    assert "wilson_95_descriptive_only" in summary["combined_not_held_out"]
    assert "NOT held out" in recall_record["claim"]
    assert recall_record["exposure"]["pattern"].startswith("Exposed")


def test_advisory_recall_record_binds_revisions_files_and_tools(recall_record):
    candidate = recall_record["candidate"]
    assert candidate["measured_commit"].startswith("dd6fc8ab")
    assert (
        candidate["pattern_lane"]["ruleset_sha256"]
        == json.loads(
            (
                _ROOT / "deploy/deep-adapters/profiles/semgrep-pattern-limited.json"
            ).read_text()
        )["ruleset_sha256"]
    )
    assert candidate["codeql_lane"]["cli_version"] == "2.27.1"
    assert all(
        case["fixes"] and case["prefix_files"] for case in recall_record["cases"]
    )
    detections = [
        hit for case in recall_record["cases"] for hit in case["pattern"]["detections"]
    ]
    assert {hit["rule"] for hit in detections} == {
        "java.disabled-hostname-verification",
        "ruby.disabled-tls-verification",
    }


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda case: case["codeql"]["detections"][0].update(line=10**6),
            "outside the fix hunks",
        ),
        (lambda case: case["codeql"].update(source_revision="0" * 40), "first parent"),
        (lambda case: case["codeql"].update(status="not_detected"), "disagrees"),
        (
            lambda case: case["prefix_files"][0].update(sha256="x"),
            "unbound pre-fix file",
        ),
    ],
)
def test_advisory_recall_record_rejects_altered_observations(
    recall_record, mutate, message
):
    altered = copy.deepcopy(recall_record)
    case = next(
        case for case in altered["cases"] if case["codeql"]["status"] == "detected"
    )
    mutate(case)
    with pytest.raises(ValueError, match=message):
        _gain["verify_recall"](altered)


def test_advisory_recall_record_rejects_inflated_summary(recall_record):
    altered = copy.deepcopy(recall_record)
    altered["summary"]["total"]["combined_detected"] = 21
    with pytest.raises(ValueError, match="does not match"):
        _gain["verify_recall"](altered)


def test_advisory_recall_prefix_cache_digest_mismatch_is_rejected(
    recall_record, tmp_path
):
    case = next(
        case for case in recall_record["cases"] if case["pattern"]["detections"]
    )
    subset = dict(recall_record, cases=[case])
    for item in case["prefix_files"]:
        target = _gain["_cache_path"](tmp_path, case, item)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"not the pre-fix source")
    with pytest.raises(ValueError, match="pre-fix bytes differ"):
        _gain["check_cache"](subset, tmp_path)


def test_advisory_recall_cli_reports_verified_record():
    assert _gain["recall_main"]([str(_RECALL_RECORD)]) == 0


def _recall_detected_case(recall_record):
    case = next(c for c in recall_record["cases"] if c["pattern"]["detections"])
    return copy.deepcopy(case), dict(recall_record, cases=[case])


def test_advisory_recall_summarize_recall_counts_lanes_and_overlap(recall_record):
    case, _ = _recall_detected_case(recall_record)
    both = copy.deepcopy(case)
    both["codeql"].update(
        status="detected", detections=[{"rule": "q", "path": "p", "line": 1}]
    )
    neither = copy.deepcopy(case)
    neither["pattern"].update(status="not_detected", detections=[])
    neither["codeql"].update(status="no_extractor", detections=[])
    summary = _gain["summarize_recall"]({"cases": [both, neither]})
    total = summary["total"]
    assert (total["cases"], total["pattern_detected"], total["codeql_detected"]) == (
        2,
        1,
        1,
    )
    assert (total["combined_detected"], total["overlap"]) == (1, 1)
    assert (total["codeql_analyzed"], total["codeql_state_no_extractor"]) == (1, 1)
    assert summary["combined_not_held_out"]["overlap"] == 1


def test_advisory_recall_fetch_cache_writes_each_bound_prefix_file(
    recall_record, tmp_path, monkeypatch
):
    case, subset = _recall_detected_case(recall_record)
    calls = []

    def fake_run(argv, check, capture_output):
        calls.append(argv)
        stdout = b""
        if argv[3] == "show":
            stdout = f"bytes of {argv[4]}".encode()
        return subprocess.CompletedProcess(argv, 0, stdout=stdout)

    monkeypatch.setattr(_gain["subprocess"], "run", fake_run)
    _gain["fetch_cache"](subset, tmp_path / "cache", tmp_path / "work")
    fetched = [argv for argv in calls if argv[3] == "fetch"]
    assert [argv[-1] for argv in fetched] == [fix["fix"] for fix in case["fixes"]]
    assert all(
        "--depth=2" in argv
        and argv[-2] == f"https://github.com/{case['repository']}.git"
        for argv in fetched
    )
    for item in case["prefix_files"]:
        written = _gain["_cache_path"](tmp_path / "cache", case, item)
        assert (
            written.read_bytes() == f"bytes of {item['parent']}:{item['path']}".encode()
        )


def test_advisory_recall_replay_pattern_requires_identical_detections(
    recall_record, tmp_path, monkeypatch
):
    _, subset = _recall_detected_case(recall_record)
    case = subset["cases"][0]
    ruleset = _ROOT / "deploy/deep-adapters/rules/semgrep-pattern-limited.yml"
    cache = tmp_path / "cache"
    results = [
        {
            "path": str(cache / case["ghsa"] / hit["parent"][:12] / hit["path"]),
            "check_id": f"deploy.deep-adapters.rules.{hit['rule']}",
            "start": {"line": hit["line"]},
        }
        for hit in case["pattern"]["detections"]
    ]

    def fake_run(argv, env, capture_output, text):
        return subprocess.CompletedProcess(
            argv, 0, stdout=json.dumps({"results": results})
        )

    monkeypatch.setattr(_gain["subprocess"], "run", fake_run)
    _gain["replay_pattern"](subset, cache, "opengrep", ruleset)
    results.append(
        dict(results[0], start={"line": results[0]["start"]["line"] + 10**6})
    )
    results[0] = dict(results[0], start={"line": results[0]["start"]["line"] + 10**6})
    with pytest.raises(ValueError, match="pattern replay differs"):
        _gain["replay_pattern"](subset, cache, "opengrep", ruleset)
    altered = tmp_path / "ruleset.yml"
    altered.write_bytes(ruleset.read_bytes() + b"\n# altered\n")
    with pytest.raises(ValueError, match="ruleset bytes differ"):
        _gain["replay_pattern"](subset, cache, "opengrep", altered)
