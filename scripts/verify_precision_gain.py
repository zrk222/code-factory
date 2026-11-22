"""Check paired precision gain or score a sealed single-arm raw sample.

Inputs are hash-bound observations, not aggregate scores. This checks their
internal consistency; source execution and label provenance require review.
``advisory-recall RECORD`` verifies the factory advisory recall record instead.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from factoryline.benchmark_lab import _wilson
from factoryline.deep_audit_io import LIMIT as MAX_EVIDENCE_BYTES
from factoryline.deep_audit_io import strict_json
from factoryline.run_metrics import _atomic_json
from factoryline.runtime_audit_common import canonical_bytes

SCHEMA = "factory.precision-gain.v1"
SINGLE_ARM_SCHEMA = "factory.precision.frozen-sample.v1"
FIELDS = ("raw", "active", "review", "supported")
DEVELOPMENT_GATE_PASS = "DEVELOPMENT_GATE_PASS"
MINIMUM_RAW_GAIN_PP = 5
_FROZEN_HASHES = ("registration_sha256", "scanner_sha256", "configuration_sha256")


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _hash(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _index(rows: list[dict], *, allow_empty=False) -> dict[str, dict]:
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("claims must be an array of objects")
    result = {}
    for row in rows:
        key = row.get("id")
        if not isinstance(key, str) or not key or key in result:
            raise ValueError("missing or duplicate claim identity")
        result[key] = row
    if not result and not allow_empty:
        raise ValueError("empty cohort")
    return result


def _metrics(rows: dict, labels: dict, population: str) -> dict:
    counts = Counter(
        labels[key]["label"] for key, row in rows.items() if _member(row, population)
    )
    tp, fp, unclear = (counts[name] for name in ("TP", "FP", "UNCLEAR"))
    decided = tp + fp
    emitted = decided + unclear
    return {
        "TP": tp,
        "FP": fp,
        "UNCLEAR": unclear,
        "decided": decided,
        "emitted": emitted,
        "precision": tp / decided if decided else None,
        "unclear_inclusive_rate": tp / emitted if emitted else None,
        "precision_label_bounds": [tp / emitted, (tp + unclear) / emitted]
        if emitted
        else None,
        "known_positive_cases_outside_population": sum(
            row["label"] == "TP" for row in labels.values()
        )
        - tp,
        "wilson_95": _wilson(tp, decided),
    }


def _member(row: dict, field: str) -> bool:
    return row["active"] or row["review"] if field == "active_or_review" else row[field]


def _version_rows(
    name: str, version: dict, contract: dict, labels: dict
) -> tuple[dict, list]:
    if not isinstance(version, dict):
        raise ValueError(f"{name}: observation must be an object")
    for key in ("context_sha256", "labels_sha256", "policy", "assumptions_sha256"):
        if version.get(key) != contract.get(key) or not contract.get(key):
            raise ValueError(f"{name}: changed or missing {key}")
    if not _hash(version.get("scanner_sha256")):
        raise ValueError(f"{name}: missing scanner seal")
    rows = _index(version["cases"])
    if set(rows) != set(labels):
        raise ValueError(f"{name}: omitted or unexpected claims")
    incomplete = []
    for key, row in rows.items():
        _validate_row(name, key, row, labels[key])
        if row.get("scan_complete") is not True:
            incomplete.append(f"{name}: incomplete {key}")
    extra = version.get("unlabelled_outputs")
    if type(extra) is not int or extra < 0:
        raise ValueError(f"{name}: missing unlabelled output count")
    if extra:
        incomplete.append(f"{name}: reconcile {extra} unlabelled outputs")
    return rows, incomplete


def _validate_row(name: str, key: str, row: dict, label: dict) -> None:
    if row.get("source_sha256") != label["source_sha256"]:
        raise ValueError(f"{name}: changed source for {key}")
    if "label" in row and row["label"] != label["label"]:
        raise ValueError(f"{name}: changed label for {key}")
    if any(type(row.get(field)) is not bool for field in FIELDS):
        raise ValueError(f"{name}: invalid population membership")
    if (row["active"] or row["review"] or row["supported"]) and not row["raw"]:
        raise ValueError(f"{name}: derived finding missing raw diagnostic")
    if row["active"] and row["review"]:
        raise ValueError(f"{name}: active and review populations overlap")
    if row["supported"] and not row["active"]:
        raise ValueError(f"{name}: supported defect must be active")


def _contract_labels(contract):
    if (
        not isinstance(contract, dict)
        or contract.get("schema") != SCHEMA
        or contract.get("scope") != "fixed_panel"
    ):
        raise ValueError("require a fixed-panel contract")
    labels = _index(contract["cases"])
    if any(
        row.get("label") not in {"TP", "FP", "UNCLEAR"}
        or not _hash(row.get("source_sha256"))
        for row in labels.values()
    ):
        raise ValueError("invalid source digest or actionable label")
    label_hash = digest(
        json.dumps(contract["cases"], sort_keys=True, separators=(",", ":")).encode()
    )
    if contract.get("labels_sha256") != label_hash:
        raise ValueError("label seal mismatch")
    if not all(
        _hash(contract.get(key)) for key in ("context_sha256", "assumptions_sha256")
    ) or not contract.get("policy"):
        raise ValueError("missing context, assumptions or policy")
    return labels


def _lost_label_memberships(before, after, labels, label, populations):
    return {
        field: [
            key
            for key in labels
            if labels[key]["label"] == label
            and _member(before[key], field)
            and not _member(after[key], field)
        ]
        for field in populations
    }


def _measurement_state(reasons, gain):
    if reasons:
        return "BLOCKED"
    if gain and gain > 0:
        return "ACTIVE_PRECISION_GAIN_FIXED_PANEL"
    return "NO_PRECISION_GAIN"


def _runtime_comparison(baseline, candidate):
    values = [arm.get("elapsed_seconds") for arm in (baseline, candidate)]
    for value in values:
        if value is not None and (
            type(value) not in (float, int) or not 0 < value < math.inf
        ):
            raise ValueError("invalid elapsed_seconds observation")
    if None in values:
        return None
    before, after = values
    return {"baseline": before, "candidate": after, "delta": after - before}


def _changed_memberships(before, after, labels):
    return {
        key: {
            "before": [f for f in FIELDS if before[key][f]],
            "after": [f for f in FIELDS if after[key][f]],
        }
        for key in labels
        if any(before[key][f] != after[key][f] for f in FIELDS)
    }


def _repair_reasons(contract, changed, lost, lost_unclear):
    reasons = []
    if changed != contract.get("expected_changes"):
        reasons.append("observed changes differ from the registered repair impact")
    if any(lost.values()):
        reasons.append("true-positive retention failed")
    if any(lost_unclear.values()):
        reasons.append("unresolved claims were removed from review")
    return reasons


def _paired_metrics(before, after, labels):
    return {
        name: {
            field: _metrics(rows, labels, field)
            for field in (*FIELDS, "active_or_review")
        }
        for name, rows in (("baseline", before), ("candidate", after))
    }


def _precision_delta(metrics, population):
    old = metrics["baseline"][population]["precision"]
    new = metrics["candidate"][population]["precision"]
    return new - old if old is not None and new is not None else None


def _comparison_state(reasons, gain, raw_gain, development_gate):
    if not development_gate:
        return _measurement_state(reasons, gain)
    if raw_gain is None or raw_gain * 100 + 1e-12 < MINIMUM_RAW_GAIN_PP:
        reasons.append("raw precision gain is below five percentage points")
    return "BLOCKED" if reasons else DEVELOPMENT_GATE_PASS


def evaluate(
    contract: dict, baseline: dict, candidate: dict, *, development_gate=False
) -> dict:
    """Reject omitted coverage, changed premises, lost TPs and unsupported gains."""
    labels = _contract_labels(contract)
    before, reasons = _version_rows("baseline", baseline, contract, labels)
    after, incomplete = _version_rows("candidate", candidate, contract, labels)
    reasons.extend(incomplete)
    changed = _changed_memberships(before, after, labels)
    lost = _lost_label_memberships(
        before, after, labels, "TP", ("raw", "active", "supported", "active_or_review")
    )
    lost_unclear = _lost_label_memberships(
        before, after, labels, "UNCLEAR", ("raw", "active_or_review")
    )
    reasons.extend(_repair_reasons(contract, changed, lost, lost_unclear))
    metrics = _paired_metrics(before, after, labels)
    gain = _precision_delta(metrics, "active")
    raw_gain = _precision_delta(metrics, "raw")
    state = _comparison_state(reasons, gain, raw_gain, development_gate)
    selection = any(
        not before[key]["review"] and after[key]["review"] for key in labels
    )
    return {
        "schema": SCHEMA,
        "state": state,
        "reasons": reasons,
        "metrics": metrics,
        "active_precision_delta": gain,
        "raw_precision_delta": raw_gain,
        "changed_claims": changed,
        "changed_claim_labels": {key: labels[key]["label"] for key in changed},
        "lost_TPs": lost,
        "lost_unclear": lost_unclear,
        "change_kind": "SELECTION_WITH_ABSTENTION"
        if selection
        else "ACTIVE_OUTPUT_CHANGE",
        "scope": "fixed_panel",
        "registered_claims": len(labels),
        "scanner_sha256": {
            "baseline": baseline["scanner_sha256"],
            "candidate": candidate["scanner_sha256"],
        },
        "labels_sha256": contract["labels_sha256"],
        "elapsed_seconds": _runtime_comparison(baseline, candidate),
        "unlabelled_outputs": {
            name: value["unlabelled_outputs"]
            for name, value in (("baseline", baseline), ("candidate", candidate))
        },
        "publication_eligible": False,
        "claim_boundary": "Paired supplied observations only; no proof of fresh sampling, label independence, execution truth or whole-scanner precision.",
    }


def _single_arm_cases(contract, selection):
    if not isinstance(selection, dict) or not all(
        _hash(contract.get(key)) and selection.get(key) == contract[key]
        for key in _FROZEN_HASHES
    ):
        raise ValueError("changed or missing frozen candidate bindings")
    if digest(canonical_bytes(selection)) != contract.get("selection_sha256"):
        raise ValueError("frozen selection seal mismatch")
    cases = _index(selection["cases"], allow_empty=True)
    status = selection["collection"]
    target = contract["sample_target"]
    if (
        type(selection.get("sample_target")) is not int
        or selection["sample_target"] != target
    ):
        raise ValueError("frozen sample target differs")
    if not isinstance(status, dict) or set(status) != {"registered", "complete"}:
        raise ValueError("invalid collection denominator")
    counts = (
        status["registered"],
        status["complete"],
        selection["observed_raw"],
        target,
    )
    if (
        any(type(count) is not int or count < 0 for count in counts)
        or status["registered"] == 0
        or status["complete"] > status["registered"]
        or len(cases) > min(selection["observed_raw"], target)
    ):
        raise ValueError("inconsistent collection or selection denominator")
    _check_selected_observations(cases, selection["admission_available"])
    return cases


def _check_selected_observations(cases, admitted):
    if type(admitted) is not bool:
        raise ValueError("invalid admission availability")
    for key, row in cases.items():
        if (
            len(key) > 160
            or key != key.strip()
            or not all(
                _hash(row.get(field))
                for field in (
                    "source_sha256",
                    "packet_sha256",
                    "report_sha256",
                    "finding_sha256",
                )
            )
        ):
            raise ValueError("invalid source, packet, report or finding binding")
        if "admitted" not in row or (
            type(row["admitted"]) is not bool
            if admitted
            else row["admitted"] is not None
        ):
            raise ValueError("admission membership contradicts availability")
    observations = {
        (row["report_sha256"], row["source_sha256"], row["finding_sha256"])
        for row in cases.values()
    }
    if len(observations) != len(cases):
        raise ValueError("selected packets repeat one raw observation")


def _single_arm_reviews(reviews, cases, selection_sha):
    if not isinstance(reviews, list) or len(reviews) != 2:
        raise ValueError("require two reviewer envelopes")
    reviewers = set()
    decisions = []
    for review in reviews:
        if (
            not isinstance(review, dict)
            or review.get("selection_sha256") != selection_sha
        ):
            raise ValueError("reviewer seal does not match the frozen selection")
        reviewer = review.get("reviewer_id")
        if (
            not isinstance(reviewer, str)
            or not 1 <= len(reviewer) <= 160
            or reviewer != reviewer.strip()
            or reviewer.casefold() in reviewers
        ):
            raise ValueError("require distinct reviewer identities")
        reviewers.add(reviewer.casefold())
        labels = _index(review["cases"], allow_empty=True)
        if labels.keys() != cases.keys():
            raise ValueError("reviewer omitted or added selected packets")
        for key, row in labels.items():
            if row.get("label") not in ("TP", "FP", "UNCLEAR") or any(
                row.get(field) != cases[key][field]
                for field in ("source_sha256", "packet_sha256")
            ):
                raise ValueError("invalid label or reviewer source/packet binding")
        decisions.append(labels)
    return decisions


def evaluate_single_arm(contract, selection, reviews):
    """Score the sealed selected raw alerts using two bound sets of labels."""
    if not isinstance(contract, dict) or contract.get("schema") != SINGLE_ARM_SCHEMA:
        raise ValueError("require a frozen single-arm contract")
    cases = _single_arm_cases(contract, selection)
    first, second = _single_arm_reviews(reviews, cases, contract["selection_sha256"])
    disagreements = [
        key for key in cases if first[key]["label"] != second[key]["label"]
    ]
    disagreement_set = set(disagreements)
    labels = {
        key: {"label": "UNCLEAR" if key in disagreement_set else first[key]["label"]}
        for key in cases
    }
    populations = {
        key: {"raw": True, "admitted": row["admitted"]} for key, row in cases.items()
    }
    raw = _metrics(populations, labels, "raw")
    admitted = (
        _metrics(populations, labels, "admitted")
        if selection["admission_available"]
        else None
    )
    collection = selection["collection"]
    incomplete = (
        collection["complete"] != collection["registered"]
        or len(cases) != contract["sample_target"]
        or not raw["decided"]
    )
    return {
        "schema": SINGLE_ARM_SCHEMA,
        "state": "INCOMPLETE" if incomplete else "SCORED_SINGLE_ARM",
        **{field: selection[field] for field in _FROZEN_HASHES},
        "selection_sha256": contract["selection_sha256"],
        "collection": {
            **collection,
            "unobserved": collection["registered"] - collection["complete"],
        },
        "observed_raw": selection["observed_raw"],
        "selected_raw": len(cases),
        "sample_target": contract["sample_target"],
        "unselected_raw": selection["observed_raw"] - len(cases),
        "admission_available": selection["admission_available"],
        "metrics": {"raw": raw, "admitted": admitted},
        "consensus": {key: row["label"] for key, row in labels.items()},
        "disagreements": disagreements,
        "publication_eligible": False,
        "claim_boundary": "Selected raw sample only. Sampling, execution, reviewer independence and blindness require external evidence.",
    }


def _read_bound(root: Path, reference: dict, *, strict=False) -> dict:
    if not isinstance(reference, dict) or not isinstance(reference.get("path"), str):
        raise ValueError("invalid evidence reference")
    path = (root / reference["path"]).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("evidence path escapes contract root")
    if strict:
        with path.open("rb") as stream:
            payload = stream.read(MAX_EVIDENCE_BYTES + 1)
    else:
        payload = path.read_bytes()
    if digest(payload) != reference["sha256"]:
        raise ValueError("evidence digest mismatch")
    return strict_json(payload) if strict else json.loads(payload)


def _operator_summary(result, output):
    if result.get("schema") == SINGLE_ARM_SCHEMA and "metrics" in result:
        return _single_arm_summary(result, output)
    lines = [result["state"]]
    for arm, metrics in result.get("metrics", {}).items():
        active = metrics["active"]
        precision = active["precision"]
        score = "undefined" if precision is None else f"{precision:.2%}"
        lines.append(
            f"{arm}: {active['TP']} TP, {active['FP']} FP, "
            f"{active['UNCLEAR']} unclear, {active['emitted']} active alerts; "
            f"precision {score}, "
            f"{active['known_positive_cases_outside_population']} known TPs outside active, "
            f"{metrics['review']['emitted']} for review"
        )
        for population, label in (("raw", "raw"), ("supported", "admitted")):
            row = metrics[population]
            precision = row["precision"]
            score = "undefined" if precision is None else f"{precision:.2%}"
            lines.append(
                f"{arm} {label}: {score} precision, "
                f"{row['UNCLEAR']} unclear of {row['emitted']} emitted"
            )
    if elapsed := result.get("elapsed_seconds"):
        lines.append(
            f"Recorded runtime: {elapsed['baseline']:.2f}s -> "
            f"{elapsed['candidate']:.2f}s"
        )
    if "metrics" in result:
        lost = sorted({key for keys in result["lost_TPs"].values() for key in keys})
        lines.append(f"Known TP losses: {', '.join(lost) or 'none'}")
    lines.extend(result.get("reasons", []))
    if "reason" in result:
        lines.append(result["reason"])
    action = {
        "BLOCKED": "Resolve the listed gaps before accepting the comparison.",
        "INVALID": "Repair the evidence inputs and verify the pair again.",
        "NO_PRECISION_GAIN": "Keep the baseline for precision work.",
        "ACTIVE_PRECISION_GAIN_FIXED_PANEL": "Review the case transitions before accepting the candidate.",
        DEVELOPMENT_GATE_PASS: "The fixed development panel meets the raw precision and retention thresholds.",
    }
    lines.append(action[result["state"]])
    lines.append(f"Case changes and evidence: {output}")
    return "\n".join(lines)


def _single_arm_summary(result, output):
    lines = [
        result["state"],
        f"Selected raw alerts: {result['selected_raw']}/{result['sample_target']} registered, "
        f"{result['unselected_raw']} observed alerts outside the sample.",
    ]
    for population, row in result["metrics"].items():
        if row is None:
            lines.append(f"{population}: unavailable")
        else:
            precision = row["precision"]
            score = "undefined" if precision is None else f"{precision:.2%}"
            lines.append(
                f"{population}: {row['TP']} TP, {row['FP']} FP, {row['UNCLEAR']} unclear, "
                f"precision {score} over {row['decided']} decided alerts"
            )
    lines.append(f"Evidence: {output}")
    return "\n".join(lines)


def _check_output_path(args, contract):
    output = args.out.resolve()
    references = [contract.get(key) for key in ("baseline", "candidate", "selection")]
    reviews = contract.get("reviewers")
    if isinstance(reviews, list):
        references.extend(reviews)
    for reference in references:
        if isinstance(reference, dict) and isinstance(reference.get("path"), str):
            if output == (args.contract.parent / reference["path"]).resolve():
                raise ValueError("--out must not replace an observation")


def _score_contract(contract, root, development_gate):
    if contract.get("schema") == SINGLE_ARM_SCHEMA:
        if development_gate:
            raise ValueError("development gate requires a paired comparison")
        reviewers = contract["reviewers"]
        if not isinstance(reviewers, list) or len(reviewers) != 2:
            raise ValueError("require two reviewer envelope references")
        evidence = {"selection": contract["selection"], "reviewers": reviewers}
        return evaluate_single_arm(
            contract,
            _read_bound(root, evidence["selection"], strict=True),
            [_read_bound(root, reference, strict=True) for reference in reviewers],
        ), evidence
    evidence = {key: contract[key] for key in ("baseline", "candidate")}
    return evaluate(
        contract,
        _read_bound(root, evidence["baseline"]),
        _read_bound(root, evidence["candidate"]),
        development_gate=development_gate,
    ), evidence


# Advisory recall record: the factory-level 20/161 measurement.
#
# The record binds each advisory to its fix and pre-fix revisions, pre-fix file
# digests, fix hunks and every individual detection. This mode recomputes the
# summary from those observations and rejects any mismatch. With --prefix-cache
# it checks the pre-fix bytes; with --opengrep it re-runs the bound pattern
# ruleset on them and requires identical detections. CodeQL results are not
# replayed here: rerun the bound argv on each source_revision for that.

RECALL_SCHEMA = "factory.advisory-recall-factory.v2"
CODEQL_STATES = {
    "detected",
    "not_detected",
    "extraction_failed",
    "no_class_query",
    "not_run",
    "no_extractor",
}
UNEXECUTED = ("extraction_failed", "no_class_query", "not_run", "no_extractor")
_SHA1 = re.compile(r"[0-9a-f]{40}")


def _in_hunk(case: dict, parent: str, path: str, line: int) -> bool:
    return any(
        item["parent"] == parent
        and item["path"] == path
        and any(low <= line <= high for low, high in item["hunk_lines"])
        for item in case["prefix_files"]
    )


def _validate_case(case: dict) -> None:
    name = case.get("ghsa")
    parents = [fix.get("parent") for fix in case.get("fixes", [])]
    if not parents or not all(
        _SHA1.fullmatch(str(fix.get(key)))
        for fix in case["fixes"]
        for key in ("fix", "parent")
    ):
        raise ValueError(f"{name}: unbound fix or parent revision")
    for item in case["prefix_files"]:
        if item["parent"] not in parents or not _hash(item["sha256"]):
            raise ValueError(f"{name}: unbound pre-fix file {item['path']}")
        if not item["hunk_lines"] or any(
            low > high for low, high in item["hunk_lines"]
        ):
            raise ValueError(f"{name}: invalid hunk ranges for {item['path']}")
    pattern = case["pattern"]
    if (pattern["status"] == "detected") != bool(pattern["detections"]):
        raise ValueError(f"{name}: pattern status disagrees with detections")
    for hit in pattern["detections"]:
        if not _in_hunk(case, hit["parent"], hit["path"], hit["line"]):
            raise ValueError(f"{name}: pattern detection outside the fix hunks")
    codeql = case["codeql"]
    if codeql["status"] not in CODEQL_STATES:
        raise ValueError(f"{name}: unknown CodeQL state")
    if (codeql["status"] == "detected") != bool(codeql.get("detections")):
        raise ValueError(f"{name}: CodeQL status disagrees with detections")
    if codeql["status"] in {"detected", "not_detected", "extraction_failed"}:
        if codeql.get("source_revision") != parents[0]:
            raise ValueError(f"{name}: CodeQL source revision is not the first parent")
    for hit in codeql.get("detections", []):
        if not _in_hunk(case, parents[0], hit["path"], hit["line"]):
            raise ValueError(f"{name}: CodeQL detection outside the fix hunks")


def summarize_recall(record: dict) -> dict:
    """Recompute every reported count from the individual case observations."""
    by_ecosystem: dict[str, Counter] = {}
    for case in record["cases"]:
        row = by_ecosystem.setdefault(case["ecosystem"], Counter())
        pattern = case["pattern"]["status"] == "detected"
        codeql = case["codeql"]["status"] == "detected"
        row.update(
            cases=1,
            pattern_detected=pattern,
            codeql_detected=codeql,
            codeql_analyzed=case["codeql"]["status"] in {"detected", "not_detected"},
            combined_detected=pattern or codeql,
            overlap=pattern and codeql,
        )
        row[f"codeql_state_{case['codeql']['status']}"] += 1
    total = sum(by_ecosystem.values(), Counter())
    keys = ["cases", "pattern_detected", "codeql_detected", "combined_detected"]
    keys += [
        "overlap",
        "codeql_analyzed",
        *(f"codeql_state_{state}" for state in UNEXECUTED),
    ]
    return {
        "by_ecosystem": {
            name: {key: row[key] for key in keys}
            for name, row in sorted(by_ecosystem.items())
        },
        "total": {key: total[key] for key in keys},
        "codeql_untuned": {
            "detected": total["codeql_detected"],
            "analyzed": total["codeql_analyzed"],
            "wilson_95_over_analyzed": _wilson(
                total["codeql_detected"], total["codeql_analyzed"]
            ),
        },
        "pattern_exposed": {
            "detected": total["pattern_detected"],
            "cases": total["cases"],
        },
        "combined_not_held_out": {
            "detected": total["combined_detected"],
            "cases": total["cases"],
            "overlap": total["overlap"],
            "wilson_95_descriptive_only": _wilson(
                total["combined_detected"], total["cases"]
            ),
        },
    }


def verify_recall(record: dict) -> dict:
    if record.get("schema") != RECALL_SCHEMA:
        raise ValueError("unexpected record schema")
    pattern = record["candidate"]["pattern_lane"]
    codeql = record["candidate"]["codeql_lane"]
    for value in (
        pattern["ruleset_sha256"],
        pattern["opengrep_binary_sha256"],
        codeql["bundle_sha256"],
        codeql["query_sets_sha256"],
    ):
        if not _hash(value):
            raise ValueError("unbound tool, ruleset or query digest")
    names = [case["ghsa"] for case in record["cases"]]
    if len(names) != len(set(names)):
        raise ValueError("duplicate advisory")
    for case in record["cases"]:
        _validate_case(case)
    summary = summarize_recall(record)
    if record.get("summary") != summary:
        raise ValueError("reported summary does not match the case observations")
    return summary


def _cache_path(cache: Path, case: dict, item: dict) -> Path:
    return cache / case["ghsa"] / item["parent"][:12] / item["path"]


def fetch_cache(record: dict, cache: Path, work: Path) -> None:
    """Write each bound pre-fix file from its source revision (needs git and network)."""

    def git(directory: Path, *args: str) -> bytes:
        return subprocess.run(
            ["git", "-C", str(directory), *args], check=True, capture_output=True
        ).stdout

    for case in record["cases"]:
        clone = work / case["ghsa"]
        clone.mkdir(parents=True, exist_ok=True)
        git(clone, "init", "-q")
        url = f"https://github.com/{case['repository']}.git"
        for fix in case["fixes"]:
            git(
                clone, "fetch", "-q", "--filter=blob:none", "--depth=2", url, fix["fix"]
            )
        for item in case["prefix_files"]:
            target = _cache_path(cache, case, item)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(git(clone, "show", f"{item['parent']}:{item['path']}"))


def check_cache(record: dict, cache: Path) -> int:
    for case in record["cases"]:
        for item in case["prefix_files"]:
            data = _cache_path(cache, case, item).read_bytes()
            if digest(data) != item["sha256"]:
                raise ValueError(
                    f"{case['ghsa']}: pre-fix bytes differ for {item['path']}"
                )
    return sum(len(case["prefix_files"]) for case in record["cases"])


def replay_pattern(record: dict, cache: Path, opengrep: str, ruleset: Path) -> None:
    import yaml

    if (
        digest(ruleset.read_bytes())
        != record["candidate"]["pattern_lane"]["ruleset_sha256"]
    ):
        raise ValueError("ruleset bytes differ from the bound ruleset")
    families = record["detection_rule"]["class_families"]
    rule_cwes = {
        rule["id"]: rule["metadata"]["cwe"]
        for rule in yaml.safe_load(ruleset.read_text())["rules"]
    }
    argv = [opengrep, "--legacy", "--disable-version-check", "--no-git-ignore"]
    argv += [
        "--disable-nosem",
        "--timeout",
        "30",
        "--config",
        str(ruleset),
        "--json",
        str(cache),
    ]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", LANG="C.UTF-8")
    report = json.loads(
        subprocess.run(argv, env=env, capture_output=True, text=True).stdout
    )
    cases = {case["ghsa"]: case for case in record["cases"]}
    observed = set()
    for result in report["results"]:
        ghsa, prefix, path = os.path.relpath(result["path"], cache).split("/", 2)
        case = cases[ghsa]
        rule = ".".join(result["check_id"].split(".")[-2:])
        wanted = {families.get(cwe) for cwe in case["cwes"]} - {None}
        if not {families.get(cwe) for cwe in rule_cwes[rule]} & wanted:
            continue
        for item in case["prefix_files"]:
            if item["path"] == path and item["parent"].startswith(prefix):
                if _in_hunk(case, item["parent"], path, result["start"]["line"]):
                    observed.add(
                        (ghsa, rule, item["parent"], path, result["start"]["line"])
                    )
    expected = {
        (case["ghsa"], hit["rule"], hit["parent"], hit["path"], hit["line"])
        for case in record["cases"]
        for hit in case["pattern"]["detections"]
    }
    if observed != expected:
        raise ValueError(
            f"pattern replay differs: missing {sorted(expected - observed)}, extra {sorted(observed - expected)}"
        )


def recall_main(argv: list[str]) -> int:
    """Verify the factory advisory recall record (``advisory-recall`` mode)."""
    parser = argparse.ArgumentParser(prog="verify_precision_gain.py advisory-recall")
    parser.add_argument("record", type=Path)
    parser.add_argument("--prefix-cache", type=Path)
    parser.add_argument(
        "--fetch-into",
        type=Path,
        help="scratch directory: rebuild --prefix-cache from GitHub first",
    )
    parser.add_argument("--opengrep", help="opengrep binary for pattern replay")
    parser.add_argument(
        "--ruleset",
        type=Path,
        default=Path("deploy/deep-adapters/rules/semgrep-pattern-limited.yml"),
    )
    args = parser.parse_args(argv)
    try:
        record = strict_json(args.record.read_bytes())
        summary = verify_recall(record)
        if args.fetch_into:
            if not args.prefix_cache:
                raise ValueError("--fetch-into requires --prefix-cache")
            fetch_cache(record, args.prefix_cache, args.fetch_into)
        files = check_cache(record, args.prefix_cache) if args.prefix_cache else None
        if args.opengrep:
            if files is None:
                raise ValueError("--opengrep requires --prefix-cache")
            replay_pattern(record, args.prefix_cache, args.opengrep, args.ruleset)
    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        subprocess.CalledProcessError,
    ) as exc:
        print(json.dumps({"state": "REJECTED", "error": str(exc)}))
        return 1
    print(
        json.dumps(
            {
                "state": "VERIFIED",
                "prefix_files_checked": files,
                "pattern_replayed": bool(args.opengrep),
                "summary": summary,
            },
            indent=1,
        )
    )
    return 0


def main() -> int:
    """Verify sealed precision inputs and write a receipt for the operator."""
    if sys.argv[1:2] == ["advisory-recall"]:
        return recall_main(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--development-gate",
        action="store_true",
        help="Require at least five points of raw precision gain on the exposed panel",
    )
    parser.add_argument(
        "--summary", action="store_true", help="Print an operator summary"
    )
    args = parser.parse_args()
    if args.out.resolve() == args.contract.resolve():
        parser.error("--out must not replace the contract")
    schema = SCHEMA
    contract_parsed = False
    try:
        with args.contract.open("rb") as stream:
            payload = stream.read(MAX_EVIDENCE_BYTES + 1)
        contract = strict_json(payload)
        if contract.get("schema") == SINGLE_ARM_SCHEMA:
            schema = SINGLE_ARM_SCHEMA
        contract_parsed = True
        try:
            _check_output_path(args, contract)
        except ValueError as exc:
            parser.error(str(exc))
        result, evidence = _score_contract(
            contract, args.contract.parent, args.development_gate
        )
        result["contract_sha256"] = digest(payload)
        result["evidence"] = evidence
    except (OSError, ValueError, KeyError, TypeError) as exc:
        if not contract_parsed and args.out.exists():
            parser.error(
                f"Cannot replace an existing output with an unreadable contract: {exc}"
            )
        result = {"schema": schema, "state": "INVALID", "reason": str(exc)}
    _atomic_json(args.out, result)
    print(
        _operator_summary(result, args.out)
        if args.summary
        else json.dumps({"state": result["state"], "out": str(args.out)})
    )
    return (
        0
        if result["state"]
        in {
            "ACTIVE_PRECISION_GAIN_FIXED_PANEL",
            DEVELOPMENT_GATE_PASS,
            "SCORED_SINGLE_ARM",
        }
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
