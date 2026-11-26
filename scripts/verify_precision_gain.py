"""Check paired precision gain or score a sealed single-arm raw sample.

Hash-bound observations are checked for consistency. Optional signed statements
authenticate the execution and label authors under a pinned trust root.
``advisory-recall RECORD`` verifies the strict advisory record and can score a
separate, signed advisory-link review.
``prepare-linked-captures PLAN`` packages saved local pattern-lane captures.
"""

from __future__ import annotations

import argparse
from base64 import urlsafe_b64decode
from collections import Counter, defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import subprocess
import sys
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from factoryline.benchmark_lab import _wilson
from factoryline.deep_audit_io import LIMIT as MAX_EVIDENCE_BYTES
from factoryline.deep_audit_io import relative_path, strict_json
from factoryline.enterprise_receipts import (
    EnterpriseReceiptError,
    verify_signed_document_value,
)
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
    if provenance := result.get("provenance"):
        lines.append(
            f"Provenance {provenance['state']}. "
            f"Review independence {provenance['review_independence']}."
        )
    lines.append(f"Evidence: {output}")
    return "\n".join(lines)


def _check_output_path(args, contract):
    output = args.out.resolve()
    if any(
        output == path.resolve() for path in (args.provenance, args.trust_root) if path
    ):
        raise ValueError("--out must not replace a provenance or trust input")
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


def _recall_case_name(case):
    if not re.fullmatch(
        r"GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}",
        str(case.get("ghsa")),
    ):
        raise ValueError("invalid advisory identity")
    if not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", str(case.get("repository"))
    ) or any(part in {".", ".."} for part in case["repository"].split("/")):
        raise ValueError("invalid repository identity")


def _recall_identity(case):
    from factoryline.deep_audit_io import relative_path

    _recall_case_name(case)
    files = case.get("prefix_files")
    if not isinstance(files, list) or not files:
        raise ValueError("nonempty source bindings required")
    seen, prefixes = set(), {}
    for item in files:
        path = relative_path(item["path"])
        parent = item["parent"]
        if not isinstance(parent, str) or not _SHA1.fullmatch(parent):
            raise ValueError("invalid source parent")
        if prefixes.setdefault(parent[:12], parent) != parent or (parent, path) in seen:
            raise ValueError("duplicate or ambiguous source binding")
        seen.add((parent, path))
        _recall_hunks(item)


def _recall_hunks(item):
    ranges = item.get("hunk_lines")
    if not isinstance(ranges, list) or not ranges:
        raise ValueError("nonempty hunk ranges required")
    for pair in ranges:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or any(type(value) is not int or value < 1 for value in pair)
            or pair[0] > pair[1]
        ):
            raise ValueError("positive ordered integer hunk bounds required")


def _recall_hit(hit):
    from factoryline.deep_audit_io import relative_path

    relative_path(hit["path"])
    if (
        type(hit["line"]) is not int
        or hit["line"] < 1
        or not isinstance(hit.get("rule"), str)
        or not hit["rule"]
    ):
        raise ValueError("invalid detection identity")


def _in_hunk(case: dict, parent: str, path: str, line: int) -> bool:
    return any(
        item["parent"] == parent
        and item["path"] == path
        and any(low <= line <= high for low, high in item["hunk_lines"])
        for item in case["prefix_files"]
    )


def _validate_case(case: dict) -> None:
    _recall_identity(case)
    name = case.get("ghsa")
    parents = [fix.get("parent") for fix in case.get("fixes", [])]
    if not parents or not all(
        _SHA1.fullmatch(str(fix.get(key)))
        for fix in case["fixes"]
        for key in ("fix", "parent")
    ):
        raise ValueError(f"{name}: unbound fix or parent revision")
    if len({parent[:12] for parent in set(parents)}) != len(set(parents)):
        raise ValueError("ambiguous parent revision prefix")
    for item in case["prefix_files"]:
        if item["parent"] not in parents or not _hash(item["sha256"]):
            raise ValueError(f"{name}: unbound pre-fix file {item['path']}")
    _recall_observations(case, parents)


def _recall_observations(case, parents):
    name = case["ghsa"]
    pattern = case["pattern"]
    if pattern["status"] not in {"detected", "not_detected"}:
        raise ValueError("unknown pattern status")
    if (pattern["status"] == "detected") != bool(pattern["detections"]):
        raise ValueError(f"{name}: pattern status disagrees with detections")
    for hit in pattern["detections"]:
        _recall_hit(hit)
        if not _in_hunk(case, hit["parent"], hit["path"], hit["line"]):
            raise ValueError(f"{name}: pattern detection outside the fix hunks")
    _recall_codeql(case, parents)


def _recall_codeql(case, parents):
    name = case["ghsa"]
    codeql = case["codeql"]
    if codeql["status"] not in CODEQL_STATES:
        raise ValueError(f"{name}: unknown CodeQL state")
    if (codeql["status"] == "detected") != bool(codeql.get("detections")):
        raise ValueError(f"{name}: CodeQL status disagrees with detections")
    if codeql["status"] in {"detected", "not_detected", "extraction_failed"}:
        if codeql.get("source_revision") != parents[0]:
            raise ValueError(f"{name}: CodeQL source revision is not the first parent")
    for hit in codeql.get("detections", []):
        _recall_hit(hit)
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
    _recall_case_name(case)
    from factoryline.deep_audit_io import relative_path

    if not isinstance(item["parent"], str) or not _SHA1.fullmatch(item["parent"]):
        raise ValueError("invalid source parent")

    relative = relative_path(f"{case['ghsa']}/{item['parent'][:12]}/{item['path']}")
    return _recall_contained(cache, relative)


def _recall_contained(root, relative):
    from factoryline.deep_audit_io import relative_path
    import stat

    root = Path(root).absolute()
    target = root / relative_path(relative)
    for path in [
        *root.parents,
        root,
        *[
            root / Path(*target.relative_to(root).parts[:index])
            for index in range(1, len(target.relative_to(root).parts) + 1)
        ],
    ]:
        if path.is_symlink() or (
            path.exists()
            and getattr(path.lstat(), "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024)
        ):
            raise ValueError("linked cache paths forbidden")
    target.resolve().relative_to(root.resolve())
    return target


def fetch_cache(record: dict, cache: Path, work: Path) -> None:
    """Write each bound pre-fix file from its source revision (needs git and network)."""

    def git(directory: Path, *args: str) -> bytes:
        from factoryline.assembly_process import run_cli_detailed

        result = run_cli_detailed(
            "git",
            ["-C", str(directory), *args],
            directory,
            timeout=180,
            max_stream_bytes=16 * 1024 * 1024,
        )
        if (
            result.get("exit_code") != 0
            or result.get("cleanup_confirmed") is not True
            or result.get("reason") is not None
        ):
            raise ValueError("bounded git fetch failed")
        raw = result["stdout"]
        if not isinstance(raw, bytes):
            raise ValueError("bounded git output bytes required")
        return raw

    verify_recall(record)
    for case in record["cases"]:
        clone = _recall_contained(work, case["ghsa"])
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
            data = git(clone, "show", f"{item['parent']}:{item['path']}")
            if digest(data) != item["sha256"]:
                raise ValueError("downloaded source digest differs")
            _recall_store_source(_cache_path(cache, case, item), item["sha256"], data)


def _recall_store_source(target, expected_hash, data):
    if target.exists():
        if _recall_file_hash(target) != expected_hash:
            raise ValueError("refusing to overwrite different cached source")
    else:
        with target.open("xb") as stream:
            stream.write(data)


def check_cache(record: dict, cache: Path) -> int:
    from factoryline.deep_audit_io import local_file

    for case in record["cases"]:
        _validate_case(case)
    for case in record["cases"]:
        for item in case["prefix_files"]:
            target = _cache_path(cache, case, item)
            source = local_file(cache, target.relative_to(cache.absolute()).as_posix())
            if _recall_file_hash(source) != item["sha256"]:
                raise ValueError(
                    f"{case['ghsa']}: pre-fix bytes differ for {item['path']}"
                )
    return sum(len(case["prefix_files"]) for case in record["cases"])


def replay_pattern(record: dict, cache: Path, opengrep: str, ruleset: Path) -> None:
    import yaml
    import shutil
    from factoryline.assembly_process import run_cli_detailed

    verify_recall(record)
    check_cache(record, cache)
    executable = Path(shutil.which(opengrep) or opengrep).resolve(strict=True)
    binary_pin = record["candidate"]["pattern_lane"]["opengrep_binary_sha256"]
    if _recall_file_hash(executable) != binary_pin:
        raise ValueError("invoked binary differs from pinned executable")
    rules_raw = _recall_read(ruleset)
    if digest(rules_raw) != record["candidate"]["pattern_lane"]["ruleset_sha256"]:
        raise ValueError("ruleset bytes differ from the bound ruleset")
    families = record["detection_rule"]["class_families"]
    rule_cwes = {
        rule["id"]: rule["metadata"]["cwe"]
        for rule in yaml.safe_load(rules_raw)["rules"]
    }
    argv = ["--legacy", "--disable-version-check", "--no-git-ignore"]
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
    facts = run_cli_detailed(
        str(executable),
        argv,
        Path.cwd(),
        env=env,
        timeout=180,
        max_stream_bytes=16 * 1024 * 1024,
    )
    report = _recall_native_report(facts, record, cache)
    observed = _recall_matching_results(report, record, cache, families, rule_cwes)
    expected = {
        (case["ghsa"], hit["rule"], hit["parent"], hit["path"], hit["line"])
        for case in record["cases"]
        for hit in case["pattern"]["detections"]
    }
    if observed != expected:
        raise ValueError(
            f"pattern replay differs: missing {sorted(expected - observed)}, extra {sorted(observed - expected)}"
        )
    if (
        _recall_file_hash(executable) != binary_pin
        or digest(_recall_read(ruleset))
        != record["candidate"]["pattern_lane"]["ruleset_sha256"]
    ):
        raise ValueError("tool or ruleset drift during replay")
    check_cache(record, cache)


def _recall_matching_results(report, record, cache, families, rule_cwes):
    cases = {case["ghsa"]: case for case in record["cases"]}
    observed = set()
    for result in report["results"]:
        ghsa, prefix, path = _recall_result_path(result["path"], cache)
        case = cases[ghsa]
        rule = ".".join(result["check_id"].split(".")[-2:])
        wanted = {families.get(cwe) for cwe in case["cwes"]} - {None}
        if not {families.get(cwe) for cwe in rule_cwes[rule]} & wanted:
            continue
        observed.update(
            (ghsa, rule, item["parent"], path, result["start"]["line"])
            for item in case["prefix_files"]
            if item["path"] == path
            and item["parent"].startswith(prefix)
            and _in_hunk(case, item["parent"], path, result["start"]["line"])
        )
    return observed


def _recall_result_path(value, cache):
    from factoryline.deep_audit_io import relative_path, local_file

    path = Path(value)
    cache = cache.absolute()
    if not path.is_absolute():
        absolute = path.absolute()
        path = absolute if absolute.is_relative_to(cache) else cache / path
    parts = path.relative_to(cache).parts
    if len(parts) < 3:
        raise ValueError("native result lacks source identity")
    source = relative_path(Path(*parts[2:]).as_posix())
    local_file(cache, relative_path(Path(*parts).as_posix()))
    return parts[0], parts[1], source


def _recall_native_report(facts, record, cache):
    if (
        facts.get("exit_code") not in {0, 1}
        or facts.get("cleanup_confirmed") is not True
        or facts.get("streams_closed") is not True
        or "reason" not in facts
        or facts.get("reason") is not None
        or len(facts.get("stderr", b"")) > 65536
    ):
        raise ValueError("native replay process incomplete")
    report = strict_json(facts["stdout"])
    if (
        report.get("errors") != []
        or report.get("paths", {}).get("skipped")
        or report.get("skipped_rules")
    ):
        raise ValueError("native replay errors or skipped inputs")
    expected = {
        _cache_path(cache, case, item).absolute()
        for case in record["cases"]
        for item in case["prefix_files"]
    }
    scanned = report.get("paths", {}).get("scanned")
    if not isinstance(scanned, list) or len(scanned) != len(expected):
        raise ValueError("native source accounting incomplete")
    observed = {_cache_native_path(value, cache) for value in scanned}
    if observed != expected:
        raise ValueError("native scanned paths differ")
    for result in report["results"]:
        ghsa, prefix, path = _recall_result_path(result["path"], cache)
        matching = [
            case
            for case in record["cases"]
            if case["ghsa"] == ghsa
            and any(
                item["parent"][:12] == prefix and item["path"] == path
                for item in case["prefix_files"]
            )
        ]
        if (
            len(matching) != 1
            or type(result["start"]["line"]) is not int
            or result["start"]["line"] < 1
        ):
            raise ValueError("unbound native result")
    return report


def _cache_native_path(value, cache):
    ghsa, prefix, path = _recall_result_path(value, cache)
    return _recall_contained(cache, f"{ghsa}/{prefix}/{path}").absolute()


def _recall_file_hash(path):
    from factoryline.candidate_lineage import _sha_file

    return _sha_file(path)


def _recall_read(path, *, max_bytes=MAX_EVIDENCE_BYTES):
    with path.open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("recall input exceeds evidence byte limit")
    return raw


PROVENANCE_SCHEMA = "factory.benchmark-provenance.v1"
STATEMENT_SCHEMA = "factory.benchmark-evidence-statement.v1"
PAYLOAD_TYPE = "application/vnd.factory.benchmark-evidence-statement.v1+json"
LINKS_SCHEMA = "factory.advisory-link-observations.v1"
LABELS_SCHEMA = "factory.advisory-link-labels.v1"
MAX_SCORE_RECEIPT_BYTES = 32_000_000


def _benchmark_evidence(path, expected_sha256=None, *, max_bytes=MAX_EVIDENCE_BYTES):
    raw = _recall_read(path, max_bytes=max_bytes)
    checksum = digest(raw)
    if expected_sha256 is not None and checksum != expected_sha256:
        raise ValueError("benchmark evidence digest mismatch")
    return strict_json(raw, max_bytes=max_bytes), checksum


def _authenticate_provenance(path, trust_path, trust_sha256, *, execution, reviews):
    """Authenticate typed statements from distinct trusted benchmark signers."""
    if path is None:
        if trust_path is not None or trust_sha256 is not None:
            raise ValueError("trust options require --provenance")
        return {"state": "UNATTESTED", "review_independence": "UNESTABLISHED"}
    if trust_path is None or not _hash(trust_sha256):
        raise ValueError("provenance requires a trust root and a pinned SHA-256")
    bundle, bundle_sha = _benchmark_evidence(path)
    trust, verified_pin = _benchmark_evidence(trust_path, trust_sha256)
    if (
        bundle.get("schema") != PROVENANCE_SCHEMA
        or not isinstance(bundle.get("reviewers"), list)
        or len(bundle["reviewers"]) != 2
        or len(reviews) != 2
    ):
        raise ValueError(
            "expected a signed execution statement and two review statements"
        )
    keys = {key["keyid"]: key["public_key"] for key in trust["keys"]}
    if len(keys) != len(trust["keys"]):
        raise ValueError("benchmark trust root repeats a key ID")
    statements = [
        (bundle["execution"], *execution, "benchmark-execution", None),
        *(
            (envelope, purpose, subject, "benchmark-review", reviewer)
            for envelope, (purpose, subject, reviewer) in zip(
                bundle["reviewers"], reviews, strict=True
            )
        ),
    ]
    signers, key_bytes, identities = [], set(), set()
    for envelope, purpose, subject, role, reviewer in statements:
        try:
            result = verify_signed_document_value(
                envelope,
                payload_type=PAYLOAD_TYPE,
                schema=STATEMENT_SCHEMA,
                trust_root=trust,
                required_key_role=role,
            )
        except EnterpriseReceiptError as exc:
            raise ValueError(f"benchmark provenance signature rejected: {exc}") from exc
        if result["payload"] != {
            "schema": STATEMENT_SCHEMA,
            "purpose": purpose,
            "subject_sha256": subject,
        }:
            raise ValueError(
                "signed benchmark statement has a different subject or purpose"
            )
        signer = result["signature"]
        identity = signer["identity"]
        if reviewer is not None and identity != reviewer:
            raise ValueError("review document identity differs from its signer")
        public = keys[signer["keyid"]]
        raw_key = urlsafe_b64decode(public + "=" * (-len(public) % 4))
        if identity.casefold() in identities or raw_key in key_bytes:
            raise ValueError(
                "benchmark evidence requires distinct signer identities and keys"
            )
        identities.add(identity.casefold())
        key_bytes.add(raw_key)
        signers.append({key: signer[key] for key in ("identity", "issuer", "keyid")})
    return {
        "state": "AUTHENTICATED_STATEMENTS",
        "trust_root_sha256": verified_pin,
        "provenance_bundle_sha256": bundle_sha,
        "execution_subject_sha256": execution[1],
        "review_subject_sha256": [review[1] for review in reviews],
        "execution_signer": signers[0],
        "review_signers": signers[1:],
        "review_independence": "UNESTABLISHED",
    }


def _finding_key(finding):
    path = relative_path(finding["path"])
    line, rule = finding["line"], finding["rule"]
    column, end_line, end_column = (
        finding.get(key) for key in ("column", "end_line", "end_column")
    )
    if (
        type(line) is not int
        or line < 1
        or not isinstance(rule, str)
        or not rule
        or any(
            value is not None and (type(value) is not int or value < 1)
            for value in (column, end_line, end_column)
        )
        or (end_line is not None and end_line < line)
    ):
        raise ValueError("invalid linked finding identity")
    return path, line, column, end_line, end_column, rule


def _emitted_findings(root, capture):
    if not _hash(capture.get("sha256")):
        raise ValueError("linked SARIF capture requires a SHA-256")
    report, _ = _benchmark_evidence(
        _recall_contained(root, capture["path"]), capture["sha256"]
    )
    runs = report.get("runs")
    if report.get("version") != "2.1.0" or not isinstance(runs, list) or not runs:
        raise ValueError("linked recall requires a SARIF 2.1.0 capture with runs")
    findings = Counter()
    for run in runs:
        if not isinstance(run, dict):
            raise ValueError("invalid SARIF run")
        invocations = run.get("invocations")
        if (
            not isinstance(invocations, list)
            or not invocations
            or not all(
                isinstance(call, dict) and call.get("executionSuccessful") is True
                for call in invocations
            )
        ):
            raise ValueError(
                "linked recall capture has no successful execution evidence"
            )
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError("invalid SARIF result list")
        for result in results:
            if not isinstance(result, dict) or not isinstance(
                result.get("locations", []), list
            ):
                raise ValueError("invalid SARIF result")
            for location in result.get("locations", []):
                if not isinstance(location, dict):
                    raise ValueError("invalid SARIF location")
                physical = location.get("physicalLocation", {})
                if not isinstance(physical, dict):
                    raise ValueError("invalid SARIF physical location")
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})
                if not isinstance(artifact, dict) or not isinstance(region, dict):
                    raise ValueError("invalid SARIF finding location")
                if "uri" in artifact and "startLine" in region:
                    key = _finding_key(
                        {
                            "path": unquote(artifact["uri"], errors="strict"),
                            "line": region["startLine"],
                            "column": region.get("startColumn"),
                            "end_line": region.get("endLine"),
                            "end_column": region.get("endColumn"),
                            "rule": result["ruleId"],
                        }
                    )
                    findings[key] += 1
    return findings


def _scope_pair(row):
    lane, scope = row["lane"], row["scope"]
    if lane not in {"pattern", "codeql"} or scope not in {
        "changed_files",
        "repository",
    }:
        raise ValueError("invalid advisory lane or scan scope")
    return lane, scope


def _pattern_report_findings(root, reference, scanned):
    if not isinstance(reference, dict) or not _hash(reference.get("sha256")):
        raise ValueError("linked pattern coverage requires the original engine report")
    report, _ = _benchmark_evidence(
        _recall_contained(root, reference["path"]), reference["sha256"]
    )
    paths = report["paths"]
    if (
        not isinstance(paths["scanned"], list)
        or sorted(relative_path(path) for path in paths["scanned"]) != sorted(scanned)
        or paths.get("skipped") != []
        or report.get("errors") != []
        or not isinstance(report.get("results"), list)
    ):
        raise ValueError("original pattern report has incomplete or different coverage")
    return Counter(
        _finding_key(
            {
                "path": item["path"],
                "rule": item["check_id"],
                "line": item["start"]["line"],
                "column": item["start"]["col"],
                "end_line": item["end"]["line"],
                "end_column": item["end"]["col"],
            }
        )
        for item in report["results"]
    )


def _source_snapshot(root, directory):
    source = _recall_contained(root, directory)
    if not source.is_dir():
        raise ValueError("linked source snapshot directory is missing")
    return {
        item.relative_to(source).as_posix(): digest(
            _recall_read(_recall_contained(source, item.relative_to(source).as_posix()))
        )
        for item in source.rglob("*")
        if item.is_file() or item.is_symlink()
    }


def _linked_capture(root, row, case, candidate):
    coverage_ref = row["coverage"]
    if not _hash(coverage_ref.get("sha256")):
        raise ValueError("linked capture requires a coverage SHA-256")
    coverage, _ = _benchmark_evidence(
        _recall_contained(root, coverage_ref["path"]), coverage_ref["sha256"]
    )
    lane, scope = _scope_pair(row)
    profile = candidate[lane + "_lane"]
    tool, configuration = (
        ("opengrep_binary_sha256", "ruleset_sha256")
        if lane == "pattern"
        else ("bundle_sha256", "query_sets_sha256")
    )
    if (
        coverage.get("schema") != "factory.advisory-engine-coverage.v1"
        or coverage.get("engine_sha256") != profile[tool]
        or coverage.get("configuration_sha256") != profile[configuration]
        or coverage.get("source_revision") != row["source_revision"]
        or coverage.get("source_tree_sha256") != row["source_tree_sha256"]
        or coverage.get("sarif_sha256") != row["capture"]["sha256"]
    ):
        raise ValueError(
            "linked capture is unbound to the source, tool, configuration or SARIF"
        )
    inventory, scanned = coverage["expected_paths"], coverage["scanned_paths"]
    if (
        not isinstance(inventory, list)
        or not inventory
        or not isinstance(scanned, list)
        or sorted(relative_path(path) for path in inventory)
        != sorted(relative_path(path) for path in scanned)
        or len(set(inventory)) != len(inventory)
        or coverage.get("skipped") != []
        or coverage.get("errors") != []
    ):
        raise ValueError("linked capture has incomplete registered scan coverage")
    source_hashes = _source_snapshot(root, row["source_root"])
    if source_hashes.keys() != set(inventory):
        raise ValueError(
            "linked capture file inventory differs from the source snapshot"
        )
    if digest(canonical_bytes(source_hashes)) != row["source_tree_sha256"]:
        raise ValueError("linked source snapshot byte fingerprints differ")
    changed = {
        item["path"]: item["sha256"]
        for item in case["prefix_files"]
        if item["parent"] == row["source_revision"]
    }
    if not changed or any(
        source_hashes.get(path) != sha for path, sha in changed.items()
    ):
        raise ValueError("linked source snapshot differs from registered pre-fix bytes")
    if scope == "changed_files" and source_hashes.keys() != changed.keys():
        raise ValueError("linked snapshot falls outside its changed-file scan scope")
    findings = _emitted_findings(root, row["capture"])
    if any(finding[0] not in source_hashes for finding in findings):
        raise ValueError("linked finding is absent from the verified source scope")
    if lane == "pattern" and findings != _pattern_report_findings(
        root, coverage.get("native_report"), scanned
    ):
        raise ValueError("original pattern report and SARIF findings differ")
    return findings


def _observations(record, record_sha256, observations, root):
    if (
        observations.get("schema") != LINKS_SCHEMA
        or observations.get("record_sha256") != record_sha256
        or observations.get("candidate_sha256")
        != digest(canonical_bytes(record["candidate"]))
        or not isinstance(observations.get("rows"), list)
    ):
        raise ValueError(
            "linked observations must bind the exact recall record and candidate"
        )
    if "score_result" in observations:
        score = observations["score_result"]
        if not isinstance(score, dict) or not _hash(score.get("sha256")):
            raise ValueError("linked score evidence requires a SHA-256")
        _capture_input(root, score)
    scopes = observations["registered_scopes"]
    if not isinstance(scopes, list) or not scopes:
        raise ValueError("register the advisory lane and scope matrix")
    groups = {_scope_pair(item) for item in scopes}
    if len(groups) != len(scopes):
        raise ValueError("duplicate registered advisory scopes")
    known = {case["ghsa"]: case for case in record["cases"]}
    completed, seen = {}, set()
    for row in observations["rows"]:
        ghsa, revision = row["ghsa"], row["source_revision"]
        lane, scope = _scope_pair(row)
        key = ghsa, lane, scope, revision
        if (
            key in seen
            or ghsa not in known
            or (lane, scope) not in groups
            or revision not in {item["parent"] for item in known[ghsa]["fixes"]}
            or row.get("state") not in {"complete", "unknown"}
        ):
            raise ValueError("invalid or duplicate linked observation")
        seen.add(key)
        if row["state"] == "unknown":
            if row.get("capture") is not None:
                raise ValueError("unknown observation cannot assert a complete capture")
            continue
        completed[key] = _linked_capture(root, row, known[ghsa], record["candidate"])
    return known, groups, completed


def _link_reviews(reviews, observations_sha256, completed):
    decisions = []
    for review in reviews:
        if (
            review.get("schema") != LABELS_SCHEMA
            or review.get("observations_sha256") != observations_sha256
            or not isinstance(review.get("reviewer_id"), str)
            or not isinstance(review.get("labels"), list)
        ):
            raise ValueError(
                "linked reviewer envelope has an invalid observation binding"
            )
        labels = {}
        for label in review["labels"]:
            key = label["ghsa"], label["lane"], label["scope"], label["source_revision"]
            verdict = label["verdict"]
            if (
                key in labels
                or key not in completed
                or verdict not in {"linked", "no_link", "unclear"}
            ):
                raise ValueError("invalid or duplicate linked reviewer verdict")
            finding = label.get("finding")
            if verdict == "linked":
                finding = _finding_key(finding)
                if completed[key][finding] != 1:
                    raise ValueError(
                        "linked reviewer finding is absent or ambiguous in signed SARIF"
                    )
            elif finding is not None:
                raise ValueError("non-link verdict cannot cite a linked finding")
            labels[key] = verdict, finding
        if labels.keys() != completed.keys():
            raise ValueError("linked reviewer omitted complete observations")
        decisions.append(labels)
    return decisions


def _result_row(counter, total):
    return {
        "registered": total,
        **{
            key: counter[key]
            for key in (
                "executed",
                "linked",
                "no_link",
                "review_unresolved",
                "linked_outside_hunk",
                "linked_outside_changed_files",
            )
        },
        "unexecuted": total - counter["executed"],
    }


def _linked_populations(record, known):
    ecosystems, families = {}, {}
    taxonomy = (record.get("detection_rule") or {}).get("class_families") or {}
    for ghsa, case in known.items():
        ecosystems.setdefault(case["ecosystem"], []).append(ghsa)
        names = {taxonomy.get(cwe) for cwe in case.get("cwes") or []} - {None}
        for name in names or {"unclassified"}:
            families.setdefault(name, []).append(ghsa)
    return ecosystems, families


def _linked_breakdown(population, counts):
    return {
        name: _result_row(sum((counts[ghsa] for ghsa in cases), Counter()), len(cases))
        for name, cases in sorted(population.items())
    }


def _linked_advisory_metrics(
    record,
    record_sha256,
    observations_path,
    labels_paths,
    provenance_path,
    trust_path,
    trust_sha256,
):
    if provenance_path is None or len(labels_paths) != 2:
        raise ValueError(
            "advisory-linked recall requires provenance and two review files"
        )
    observations, obs_sha = _benchmark_evidence(observations_path)
    review_items = [_benchmark_evidence(path) for path in labels_paths]
    reviews = [review for review, _ in review_items]
    provenance = _authenticate_provenance(
        provenance_path,
        trust_path,
        trust_sha256,
        execution=("advisory-execution", obs_sha),
        reviews=[
            ("advisory-link-labels", review_sha, review["reviewer_id"])
            for review, review_sha in review_items
        ],
    )
    known, groups, complete = _observations(
        record, record_sha256, observations, observations_path.parent
    )
    first, second = _link_reviews(reviews, obs_sha, complete)
    ecosystems, families = _linked_populations(record, known)
    results = []
    lane_links = {"pattern": set(), "codeql": set()}
    for lane, scope in sorted(groups):
        counts = {ghsa: Counter() for ghsa in known}
        for ghsa, case in known.items():
            parents = {item["parent"] for item in case["fixes"]}
            keys = [
                (ghsa, lane, scope, rev)
                for rev in parents
                if (ghsa, lane, scope, rev) in complete
            ]
            if not keys:
                continue
            counter = counts[ghsa]
            counter["executed"] += 1
            matched = [
                (key[3], first[key][1])
                for key in keys
                if first[key] == second[key] and first[key][0] == "linked"
            ]
            if matched:
                lane_links[lane].add(ghsa)
                counter["linked"] += 1
                counter["linked_outside_hunk"] += any(
                    not _in_hunk(case, revision, finding[0], finding[1])
                    for revision, finding in matched
                )
                counter["linked_outside_changed_files"] += any(
                    not any(
                        item["parent"] == revision and item["path"] == finding[0]
                        for item in case["prefix_files"]
                    )
                    for revision, finding in matched
                )
            elif len(keys) == len(parents) and all(
                first[key] == second[key] == ("no_link", None) for key in keys
            ):
                counter["no_link"] += 1
            else:
                counter["review_unresolved"] += 1
        results.append(
            {
                "lane": lane,
                "scope": scope,
                "total": _result_row(sum(counts.values(), Counter()), len(known)),
                "by_ecosystem": _linked_breakdown(ecosystems, counts),
                "by_family": _linked_breakdown(families, counts),
            }
        )
    return {
        "state": "ADJUDICATED_SIGNED_OBSERVATIONS" if complete else "NOT_MEASURED",
        "provenance": provenance,
        "scope_results": results,
        "combined": {
            "registered": len(known),
            "unique_linked": len(lane_links["pattern"] | lane_links["codeql"]),
            "linked_by_both_lanes": len(lane_links["pattern"] & lane_links["codeql"]),
        },
        "record_sha256": record_sha256,
        "observations_sha256": obs_sha,
        "publication_eligible": False,
        "claim_boundary": "Supplemental associations on supplied observations. Blind and whole-product recall remain unestablished.",
    }


def _add_provenance_options(parser):
    parser.add_argument("--provenance", type=Path, help="Role-bound signed statements")
    parser.add_argument("--trust-root", type=Path)
    parser.add_argument(
        "--trust-root-sha256", help="Independently approved trust-root hash"
    )


def _precision_provenance(args, contract):
    if args.provenance is None:
        return _authenticate_provenance(
            None,
            args.trust_root,
            args.trust_root_sha256,
            execution=None,
            reviews=[],
        )
    if contract.get("schema") != SINGLE_ARM_SCHEMA:
        raise ValueError("precision provenance requires a sealed single-arm contract")
    reviews = [
        (
            "precision-labels",
            item["sha256"],
            _read_bound(args.contract.parent, item, strict=True)["reviewer_id"],
        )
        for item in contract["reviewers"]
    ]
    return _authenticate_provenance(
        args.provenance,
        args.trust_root,
        args.trust_root_sha256,
        execution=("precision-execution", contract["selection"]["sha256"]),
        reviews=reviews,
    )


def _advisory_links(args, record, record_sha256):
    if args.linked_observations is None:
        if (
            args.link_review
            or args.provenance
            or args.trust_root
            or args.trust_root_sha256
        ):
            raise ValueError(
                "linked reviews and provenance require --linked-observations"
            )
        return {"state": "NOT_MEASURED"}
    return _linked_advisory_metrics(
        record,
        record_sha256,
        args.linked_observations,
        args.link_review,
        args.provenance,
        args.trust_root,
        args.trust_root_sha256,
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
    parser.add_argument("--linked-observations", type=Path)
    parser.add_argument("--link-review", type=Path, action="append", default=[])
    _add_provenance_options(parser)
    args = parser.parse_args(argv)
    try:
        record_bytes = _recall_read(args.record)
        record = strict_json(record_bytes)
        summary = verify_recall(record)
        linked = _advisory_links(args, record, digest(record_bytes))
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
                "measurement": "STRICT_OLD_SIDE_HUNK",
                "summary": summary,
                "advisory_linked_recall": linked,
            },
            indent=1,
        )
    )
    return 0


def _capture_artifact(root, prefix, payload):
    name = f"{prefix}-{digest(canonical_bytes(payload))}.json"
    path = _recall_contained(root, name)
    if path.exists():
        existing, _ = _benchmark_evidence(path)
        if existing != payload:
            raise ValueError("capture artifact conflicts with existing evidence")
    else:
        _atomic_json(path, payload)
    return {"path": name, "sha256": _recall_file_hash(path)}


def _capture_input(root, reference, *, json_limit=None):
    name = reference["path"] if isinstance(reference, dict) else reference
    path = _recall_contained(root, name)
    report, checksum = (
        _benchmark_evidence(path, max_bytes=json_limit)
        if json_limit is not None
        else (None, _recall_file_hash(path))
    )
    if isinstance(reference, dict) and reference.get("sha256") != checksum:
        raise ValueError("saved capture differs from the recorded scanner fingerprint")
    return name, checksum, report


def _score_capture_index(root, reference, pattern):
    name, checksum, report = _capture_input(
        root, reference, json_limit=MAX_SCORE_RECEIPT_BYTES
    )
    schema = report["schema"]
    standalone = schema == "factory.recall-result.v1"
    if not standalone and schema != "factory.recall-evaluation.v1":
        raise ValueError("unsupported saved score schema")
    kind = "score" if standalone else "evaluation"
    engine = report.get("engine")
    if not isinstance(engine, dict) or not engine.get("executable_sha256"):
        raise ValueError(
            f"saved {kind} has no scanner fingerprint; regenerate the receipt"
        )
    if engine["executable_sha256"] != pattern["opengrep_binary_sha256"]:
        raise ValueError(f"saved {kind} engine differs from the registered candidate")
    sections = (
        [report] if standalone else [batch["after_evidence"] for batch in report["dev"]]
    )
    rows = {}
    for section in sections:
        if section["ruleset_sha256"] != pattern["ruleset_sha256"]:
            raise ValueError(
                "saved score ruleset differs from the registered candidate"
            )
        for case in section["cases"]:
            revisions = case.get("revisions")
            if revisions is None:
                continue
            key = case["ghsa"], revisions["old"]
            if key in rows:
                raise ValueError("duplicate saved score case and revision")
            rows[key] = case
    return {"path": name, "sha256": checksum}, rows


def _verified_score_capture(case):
    notes = case["scan_sides"]["old"]
    capture = case["captures"]["old"]
    if not isinstance(notes, dict) or not isinstance(capture, dict):
        raise ValueError("saved score has no successful old-side capture")
    if notes.get("failed_exit") is not False or notes.get("exit_code") not in (0, 1):
        raise ValueError("saved score has no successful old-side capture")
    if any(
        notes.get(key) != 0 for key in ("timeouts", "blocking_parse_errors", "other")
    ):
        raise ValueError("saved score contains old-side execution errors")
    for key, field in (
        ("sarif", "report_sha256"),
        ("native_report", "coverage_report_sha256"),
    ):
        if not isinstance(capture.get(key), dict) or capture[key].get(
            "sha256"
        ) != notes.get(field):
            raise ValueError(
                "saved score capture references disagree with scanner receipts"
            )
    return capture


def _saved_pattern_capture(entry, score_index):
    if score_index is None:
        return entry, None
    manual_fields = {"source_root", "sarif", "native_report"}
    if entry["scope"] != "changed_files" or manual_fields.intersection(entry):
        raise ValueError(
            "score-derived capture requires an unambiguous changed-file scope"
        )
    case = score_index.get((entry["ghsa"], entry["source_revision"]))
    if case is None:
        raise ValueError("saved score has no capture at the registered revision")
    old_packets = case["source_packets"]["old"]
    packets = {item["path"]: item["sha256"] for item in old_packets}
    if len(old_packets) != len(packets):
        raise ValueError("duplicate paths in saved score source packets")
    return _verified_score_capture(case), packets


def _prepare_pattern_row(root, row, capture, packets, pattern):
    raw_path, raw_sha, raw = _capture_input(
        root, capture["native_report"], json_limit=MAX_EVIDENCE_BYTES
    )
    sarif_path, sarif_sha, _ = _capture_input(root, capture["sarif"])
    if raw.get("version") != pattern["opengrep_version"]:
        raise ValueError("original pattern report version differs from the candidate")
    source = capture["source_root"]
    files = _source_snapshot(root, source)
    if packets is not None and packets != files:
        raise ValueError("source snapshot differs from saved score packet fingerprints")
    tree = digest(canonical_bytes(files))
    coverage = _capture_artifact(
        root,
        "coverage",
        {
            "schema": "factory.advisory-engine-coverage.v1",
            "engine_sha256": pattern["opengrep_binary_sha256"],
            "configuration_sha256": pattern["ruleset_sha256"],
            "source_revision": row["source_revision"],
            "source_tree_sha256": tree,
            "sarif_sha256": sarif_sha,
            "expected_paths": sorted(files),
            "scanned_paths": raw["paths"]["scanned"],
            "skipped": raw["paths"]["skipped"],
            "errors": raw["errors"],
            "native_report": {"path": raw_path, "sha256": raw_sha},
        },
    )
    row.update(
        source_root=source,
        source_tree_sha256=tree,
        coverage=coverage,
        capture={"path": sarif_path, "sha256": sarif_sha},
    )


def prepare_captures_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="verify_precision_gain.py prepare-linked-captures"
    )
    parser.add_argument("plan", type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.plan.absolute().parent
        plan, _ = _benchmark_evidence(_recall_contained(root, args.plan.name))
        if plan.get("schema") != "factory.advisory-capture-plan.v1":
            raise ValueError("unexpected advisory capture plan schema")
        record, record_sha = _benchmark_evidence(
            _recall_contained(root, plan["record"])
        )
        verify_recall(record)
        pattern = record["candidate"]["pattern_lane"]
        tool, rules = (
            _recall_file_hash(_recall_contained(root, plan[key]))
            for key in ("opengrep", "ruleset")
        )
        if (tool, rules) != (
            pattern["opengrep_binary_sha256"],
            pattern["ruleset_sha256"],
        ):
            raise ValueError("capture tools do not match the registered candidate")
        observations = {
            "schema": LINKS_SCHEMA,
            "record_sha256": record_sha,
            "candidate_sha256": digest(canonical_bytes(record["candidate"])),
            "registered_scopes": plan["registered_scopes"],
            "rows": [],
        }
        score_index = None
        if "score_result" in plan:
            observations["score_result"], score_index = _score_capture_index(
                root, plan["score_result"], pattern
            )
        for entry in plan["rows"]:
            row = {
                key: entry[key]
                for key in ("ghsa", "lane", "scope", "source_revision", "state")
            }
            if row["state"] == "complete":
                if row["lane"] != "pattern":
                    raise ValueError(
                        "capture preparation requires an original pattern report"
                    )
                capture, packets = _saved_pattern_capture(entry, score_index)
                _prepare_pattern_row(root, row, capture, packets, pattern)
            observations["rows"].append(row)
        _, _, completed = _observations(record, record_sha, observations, root)
        output = _capture_artifact(root, "linked-observations", observations)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        print(json.dumps({"state": "REJECTED", "error": str(exc)}))
        return 1
    print(
        json.dumps(
            {
                "state": "PREPARED",
                "observations": output,
                "complete_captures": len(completed),
                "provenance": "UNATTESTED",
            }
        )
    )
    return 0


def main() -> int:
    """Verify sealed precision inputs and write a receipt for the operator."""
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
    _add_provenance_options(parser)
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
        result["provenance"] = _precision_provenance(args, contract)
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


VERDICTS = ("TP", "FP", "UNCLEAR")
FAMILIES = (
    ({"CWE-22", "CWE-23", "CWE-73", "CWE-59"}, "path traversal"),
    ({"CWE-79", "CWE-80", "CWE-116"}, "XSS / HTML injection"),
    ({"CWE-78", "CWE-77", "CWE-88"}, "command injection"),
    ({"CWE-89"}, "SQL injection"),
    ({"CWE-502"}, "unsafe deserialization"),
    ({"CWE-295", "CWE-319"}, "TLS / transport verification"),
)
INSTRUCTIONS = (
    "For each item, decide whether the marked line (>) is a real instance of the claimed "
    "weakness: attacker- or user-influenced data can reach it in a realistic deployment of "
    "this library or application, with no effective validation in the shown or implied code. "
    "If a span is present, it gives the start column, end-line offset, and end column. "
    "Answer TP, FP or UNCLEAR, with one sentence of reasoning. Judge each item on its own; do "
    "not look up advisories, fixes or other labels."
)
# A rule is eligible for the default tier only when the lower Wilson bound of
# its adjudicated precision clears this, on at least MIN_DECIDED decided alerts.
DEFAULT_TIER_LOWER_BOUND = 0.80
REVIEW_TIER_LOWER_BOUND = 0.30
MIN_DECIDED = 20


def write_json(path: Path, value) -> str:
    data = (json.dumps(value, indent=1, sort_keys=False) + "\n").encode()
    path.write_bytes(data)
    return digest(data)


def read_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def review_wilson(successes: int, total: int) -> list[float] | None:
    """Report the shared Wilson interval at the ledger's four-decimal precision."""
    bounds = _wilson(successes, total)
    return [round(bound, 4) for bound in bounds] if bounds is not None else None


def beta_mean(successes: int, failures: int) -> float:
    """Posterior mean under a uniform Beta(1, 1) prior."""
    return round((successes + 1) / (successes + failures + 2), 4)


def weakness(cwes: list[str]) -> str:
    found = set(cwes)
    for members, label in FAMILIES:
        if found & members:
            return label
    return ", ".join(sorted(found)) or "unspecified"


def rule_cwes(rules_path: Path) -> dict[str, list[str]]:
    import yaml  # PyYAML ships with the factory extra.

    rules = yaml.safe_load(rules_path.read_text(encoding="utf-8"))["rules"]
    return {rule["id"]: list(rule.get("metadata", {}).get("cwe", [])) for rule in rules}


def item_id(alert: dict) -> str:
    raw = f"{alert['case']}|{alert['path']}|{alert['line']}|{alert['rule']}"
    if alert.get("span") is not None:
        raw += "|" + json.dumps(alert["span"], sort_keys=True, separators=(",", ":"))
    return digest(raw.encode())[:12]


def context(root: Path, path: str, line: int, radius: int = 5) -> str:
    source = (root / path).read_text(encoding="utf-8", errors="replace").splitlines()
    first, last = max(0, line - 1 - radius), min(len(source), line + radius)
    return "\n".join(
        f"{index + 1:5}{'>' if index + 1 == line else ' '} {source[index]}"
        for index in range(first, last)
    )


def stratified(alerts: list[dict], per_rule: int, seed: int) -> list[dict]:
    """At most per_rule alerts per rule, drawn with a fixed seed, then shuffled."""
    by_rule: dict[str, list[dict]] = defaultdict(list)
    for alert in alerts:
        by_rule[alert["rule"]].append(alert)
    rng = random.Random(seed)
    chosen = []
    for rule in sorted(by_rule):
        rows = sorted(by_rule[rule], key=item_id)
        chosen.extend(rows if len(rows) <= per_rule else rng.sample(rows, per_rule))
    rng.shuffle(chosen)
    return chosen


def wilson_exact(successes: int, total: int) -> tuple[float, float] | None:
    """Unrounded Wilson 95% interval; tier decisions use these values only."""
    if total <= 0:
        return None
    z = 1.96
    phat = successes / total
    denominator = 1 + z * z / total
    centre = (phat + z * z / (2 * total)) / denominator
    radius = (
        z
        * math.sqrt(phat * (1 - phat) / total + z * z / (4 * total * total))
        / denominator
    )
    return max(0.0, centre - radius), min(1.0, centre + radius)


def rule_revision(rule: dict) -> str:
    """Digest of a rule's matching semantics; message and metadata edits keep it."""
    semantic = {
        key: value
        for key, value in rule.items()
        if key not in ("message", "metadata", "severity")
    }
    return digest(json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode())


def rule_revisions(rules_path: Path) -> dict[str, str]:
    import yaml  # PyYAML ships with the factory extra.

    rules = yaml.safe_load(rules_path.read_text(encoding="utf-8"))["rules"]
    return {rule["id"]: rule_revision(rule) for rule in rules}


def build_packet(args) -> None:
    cwes = rule_cwes(Path(args.rules))
    revisions = rule_revisions(Path(args.rules))
    unique = {}
    for alert in read_json(Path(args.alerts)):
        unique.setdefault(item_id(alert), alert)
    chosen = stratified(list(unique.values()), args.per_rule, args.seed)
    items, key = [], {}
    for alert in chosen:
        identity = item_id(alert)
        source = Path(alert["root"]) / alert["path"]
        items.append(
            {
                "item": identity,
                "repository_case": alert["case"],
                "file": alert["path"],
                "line": alert["line"],
                **({"span": alert["span"]} if alert.get("span") is not None else {}),
                "claimed_weakness": weakness(cwes.get(alert["rule"], [])),
                "context": context(Path(alert["root"]), alert["path"], alert["line"]),
            }
        )
        key[identity] = {
            "rule": alert["rule"],
            "rule_revision": revisions.get(alert["rule"]),
            "source_sha256": digest(source.read_bytes()),
            "span": alert.get("span"),
            "on_fix_hunk": bool(alert.get("on_fix_hunk")),
        }
    packet = {
        "schema": "factory.label-packet.v1",
        "cohort": args.cohort,
        "seed": args.seed,
        "per_rule_cap": args.per_rule,
        "rules_sha256": digest(Path(args.rules).read_bytes()),
        "instructions": INSTRUCTIONS,
        "items": items,
    }
    packet_sha = write_json(Path(args.out), packet)
    write_json(Path(args.key), {"packet_sha256": packet_sha, "key": key})
    print(
        json.dumps(
            {
                "items": len(items),
                "rules": dict(Counter(k["rule"] for k in key.values())),
                "packet_sha256": packet_sha,
            }
        )
    )


def labels_by_position(packet: dict, labels: dict, packet_sha: str) -> list[dict]:
    """Verify reviewer labels against the exact packet before pairing positions."""
    if labels.get("packet_sha256") != packet_sha:
        raise SystemExit("reviewer labels belong to a different packet")
    rows = labels["labels"]
    if [row["item"] for row in rows] != [item["item"] for item in packet["items"]]:
        raise SystemExit("labels do not follow the packet's item order")
    for row in rows:
        if row["verdict"] not in VERDICTS:
            raise SystemExit(f"invalid verdict {row['verdict']!r} for {row['item']}")
    return rows


def review_label_pair(paths, packet, packet_sha, reviewers=None):
    """Pair two independently identified label documents."""
    documents = [read_json(Path(path)) for path in paths]
    identities = [document.get("reviewer") for document in documents]
    if any(not isinstance(name, str) or not name.strip() for name in identities):
        raise SystemExit("both label documents need reviewer identities")
    if identities[0] == identities[1] or (
        reviewers is not None and identities != list(reviewers)
    ):
        raise SystemExit(
            "label documents must identify the two distinct expected reviewers"
        )
    return [labels_by_position(packet, document, packet_sha) for document in documents]


def _file_pin(path) -> dict:
    return {"file": Path(path).name, "sha256": digest(Path(path).read_bytes())}


def build_judge(args) -> None:
    """Disagreements for the judge, bound to the exact packet, label pair and context."""
    packet_bytes = Path(args.packet).read_bytes()
    packet, packet_sha = json.loads(packet_bytes), digest(packet_bytes)
    first, second = review_label_pair(args.labels, packet, packet_sha)
    reviewers = [read_json(Path(path))["reviewer"] for path in args.labels]
    supplement = {}
    if args.context:
        document = read_json(Path(args.context))
        if document.get("packet_sha256") != packet_sha:
            raise SystemExit("context supplement belongs to a different packet")
        supplement = {row["item"]: row for row in document["items"]}
    disagreements = []
    for index, (item, a, b) in enumerate(zip(packet["items"], first, second)):
        if a["verdict"] == b["verdict"]:
            continue
        extra = supplement.get(item["item"], {})
        disagreements.append(
            {
                "position": index,
                **item,
                **{
                    key: extra[key]
                    for key in ("context_wide", "file_header_imports")
                    if key in extra
                },
                "reviewer_1": {"verdict": a["verdict"], "reason": a.get("reason", "")},
                "reviewer_2": {"verdict": b["verdict"], "reason": b.get("reason", "")},
            }
        )
    inputs = {
        "packet": {"sha256": packet_sha},
        "labels": [
            {**_file_pin(path), "reviewer": name}
            for path, name in zip(args.labels, reviewers)
        ],
    }
    if args.context:
        inputs["context_supplement"] = _file_pin(args.context)
    judge_sha = write_json(
        Path(args.out),
        {
            "schema": "factory.judge-packet.v2",
            "packet_sha256": packet_sha,
            "inputs": inputs,
            "shown_to_judge": [
                "context",
                "context_wide",
                "file_header_imports",
                "reviewer_1",
                "reviewer_2",
            ]
            if args.context
            else ["context", "reviewer_1", "reviewer_2"],
            "disagreements": disagreements,
        },
    )
    print(
        json.dumps(
            {
                "positions": len(first),
                "disagreements": len(disagreements),
                "judge_packet_sha256": judge_sha,
            }
        )
    )


def review_judge_verdicts(document, packet_sha, disagreements, judge_packet_sha=None):
    """Verify the judge covered exactly its assigned positions and items."""
    if document.get("packet_sha256") != packet_sha:
        raise SystemExit("judge verdicts belong to a different packet")
    if (
        judge_packet_sha is not None
        and document.get("judge_packet_sha256") != judge_packet_sha
    ):
        raise SystemExit("judge verdicts belong to a different judge assignment")
    return _assigned_judge_verdicts(document["verdicts"], disagreements)


def _assigned_judge_verdicts(rows, disagreements):
    """Bind every verdict to one distinct assigned position."""
    verdicts = {}
    for row in rows:
        position = row.get("position")
        if (
            type(position) is not int
            or position in verdicts
            or position not in disagreements
        ):
            raise SystemExit("judge supplied a duplicate or unassigned position")
        if (
            row.get("item") != disagreements[position]
            or row.get("verdict") not in VERDICTS
        ):
            raise SystemExit("judge item or verdict does not match the assignment")
        verdicts[position] = row["verdict"]
    if set(verdicts) != set(disagreements):
        raise SystemExit("judge left assigned disagreements without a verdict")
    return verdicts


def _verify_judge_assignment(path, packet_sha, label_paths, disagreements) -> str:
    """The judge assignment must come from this packet and this exact label pair."""
    assignment_bytes = Path(path).read_bytes()
    assignment = json.loads(assignment_bytes)
    if assignment.get("packet_sha256") != packet_sha:
        raise SystemExit("judge assignment belongs to a different packet")
    inputs = assignment.get("inputs", {})
    pinned = [row["sha256"] for row in inputs.get("labels", [])] or [
        inputs.get("labels_reviewer_1"),
        inputs.get("labels_reviewer_2"),
    ]  # the first exposed assignment pinned the pair under these two names
    if pinned != [digest(Path(p).read_bytes()) for p in label_paths]:
        raise SystemExit("judge assignment was built from a different label pair")
    assigned = {row["position"]: row["item"] for row in assignment["disagreements"]}
    if assigned != disagreements:
        raise SystemExit(
            "judge assignment positions differ from the label pair's disagreements"
        )
    return digest(assignment_bytes)


def _adjudication_inputs(args, packet_sha: str, key_bytes: bytes) -> dict:
    """Pin every input the adjudication read, by file name and digest."""
    inputs = {
        "packet": {"sha256": packet_sha},
        "key": {"sha256": digest(key_bytes)},
        "labels": [
            {**_file_pin(path), "reviewer": name}
            for path, name in zip(args.labels, args.reviewer)
        ],
    }
    for name, path in (
        ("judge_assignment", args.judge_packet),
        ("judge", args.judge),
        ("context_supplement", args.context),
    ):
        if path:
            inputs[name] = _file_pin(path)
    if args.effort_receipt:
        inputs["effort_receipts"] = [_file_pin(path) for path in args.effort_receipt]
    return inputs


def adjudicate(args) -> None:
    packet_bytes = Path(args.packet).read_bytes()
    packet, packet_sha = json.loads(packet_bytes), digest(packet_bytes)
    key_bytes = Path(args.key).read_bytes()
    sealed = json.loads(key_bytes)
    if sealed["packet_sha256"] != packet_sha:
        raise SystemExit("key belongs to a different packet")
    first, second = review_label_pair(args.labels, packet, packet_sha, args.reviewer)
    disagreements = {
        index: item["item"]
        for index, (item, a, b) in enumerate(zip(packet["items"], first, second))
        if a["verdict"] != b["verdict"]
    }
    judged, assignment_sha = {}, None
    if args.judge:
        if not args.judge_packet:
            raise SystemExit(
                "judge verdicts need the judge assignment they answer (--judge-packet)"
            )
        assignment_sha = _verify_judge_assignment(
            args.judge_packet, packet_sha, args.labels, disagreements
        )
        judged = review_judge_verdicts(
            read_json(Path(args.judge)), packet_sha, disagreements, assignment_sha
        )
    rows, final = [], {}
    for index, (item, a, b) in enumerate(zip(packet["items"], first, second)):
        if a["verdict"] == b["verdict"]:
            verdict, judge = a["verdict"], None
        elif index in judged:
            verdict = judge = judged[index]
        else:
            raise SystemExit(f"disagreement at position {index} has no judge verdict")
        if final.setdefault(item["item"], verdict) != verdict:
            raise SystemExit(
                f"duplicate item {item['item']} received different final verdicts"
            )
        rows.append(
            {
                "position": index,
                "item": item["item"],
                "case": item["repository_case"],
                "file": item["file"],
                "line": item["line"],
                **sealed["key"][item["item"]],
                "reviewer_1": a["verdict"],
                "reviewer_2": b["verdict"],
                "judge": judge,
                "final": verdict,
            }
        )
    inputs = _adjudication_inputs(args, packet_sha, key_bytes)
    unique = {row["item"]: row for row in rows}
    out = {
        "schema": "factory.adjudicated-precision.v3",
        "packet_sha256": packet_sha,
        "reviewers": list(args.reviewer),
        "judge": args.judge_name,
        "inputs": inputs,
        "independence": "AI reviewers and judge unless stated otherwise; independence from AI is unestablished",
        "agreed_positions": sum(row["judge"] is None for row in rows),
        "positions": len(rows),
        "unresolved": {
            "jointly_unclear": sorted(
                r["item"]
                for r in unique.values()
                if r["judge"] is None and r["final"] == "UNCLEAR"
            ),
            "judge_unclear": sorted(
                r["item"] for r in unique.values() if r["judge"] == "UNCLEAR"
            ),
        },
        "final_counts": dict(Counter(row["final"] for row in unique.values())),
        "rows": rows,
    }
    print(
        json.dumps(
            {
                "digest": write_json(Path(args.out), out),
                "unique": len(final),
                "verdicts": out["final_counts"],
            }
        )
    )


def tier_for(tp: int, fp: int) -> str:
    """Tier from the full-precision Wilson lower bound; rounding never promotes."""
    decided = tp + fp
    bounds = wilson_exact(tp, decided)
    if decided < MIN_DECIDED or bounds is None:
        return "unqualified"
    if bounds[0] >= DEFAULT_TIER_LOWER_BOUND:
        return "default"
    return "review" if bounds[0] >= REVIEW_TIER_LOWER_BOUND else "retire"


def _alert_identity(row: dict) -> tuple:
    """Exact alert identity: source snapshot, location, rule and rule semantics."""
    span = row.get("span")
    location = (row["line"], json.dumps(span, sort_keys=True) if span is not None else None)
    return (
        row.get("case") or row.get("repository_case"),
        row["file"],
        row.get("source_sha256"),
        location,
        row["rule"],
        row.get("rule_revision"),
    )


def _rule_confidence_summary(counts, stale, origins):
    """Calculate confidence and provenance for one rule's deduplicated alerts."""
    tp, fp, unclear = counts["TP"], counts["FP"], counts["UNCLEAR"]
    decided = tp + fp
    total = decided + unclear
    return {
        "tp": tp,
        "fp": fp,
        "unclear": unclear,
        "decided": decided,
        "decision_coverage": round(decided / total, 4) if total else None,
        "precision": round(tp / decided, 4) if decided else None,
        "wilson95": review_wilson(tp, decided),
        "all_alert_precision_wilson95": review_wilson(tp, total),
        "beta_mean": beta_mean(tp, fp),
        "evidence_tier": tier_for(tp, fp),
        "stale_rows_excluded": stale,
        "sample_origins": sorted(origins),
    }


def compute_ledger(paths, revisions: dict[str, str] | None = None) -> dict:
    """Per-rule confidence; independent of input order and of duplicate observations."""
    verdicts: dict[tuple, str] = {}
    origins: dict[tuple, set] = defaultdict(set)
    stale: Counter = Counter()
    sources = []
    for path in sorted(paths, key=lambda p: digest(Path(p).read_bytes())):
        data_bytes = Path(path).read_bytes()
        data = json.loads(data_bytes)
        sha = digest(data_bytes)
        sources.append(
            {
                "file": Path(path).name,
                "sha256": sha,
                "independence": data.get("independence", "unstated"),
            }
        )
        for row in data["rows"]:
            # A row without a revision, or for a rule absent from the candidate,
            # cannot vouch for the candidate's rule semantics.
            if revisions is not None and (
                row.get("rule_revision") is None
                or row.get("rule_revision") != revisions.get(row["rule"])
            ):
                stale[row["rule"]] += 1
                continue
            identity = _alert_identity(row)
            if verdicts.setdefault(identity, row["final"]) != row["final"]:
                raise SystemExit(f"conflicting verdicts for one alert: {identity}")
            origins[identity].add(sha)
    per_rule: dict[str, Counter] = defaultdict(Counter)
    rule_origins: dict[str, set] = defaultdict(set)
    for identity, verdict in verdicts.items():
        per_rule[identity[4]][verdict] += 1
        rule_origins[identity[4]] |= origins[identity]
    rules = {
        rule: _rule_confidence_summary(
            per_rule.get(rule, Counter()),
            stale.get(rule, 0),
            rule_origins.get(rule, ()),
        )
        for rule in sorted(set(per_rule) | set(stale))
    }
    return {
        "schema": "factory.rule-confidence.v2",
        "policy": {
            "default_tier_wilson_lower": DEFAULT_TIER_LOWER_BOUND,
            "review_tier_wilson_lower": REVIEW_TIER_LOWER_BOUND,
            "minimum_decided_alerts": MIN_DECIDED,
            "tier_bounds": "full-precision Wilson; displayed bounds are rounded",
            "rule_binding": "rule revision digests"
            if revisions is not None
            else "unbound",
        },
        "sources": sources,
        "rules": rules,
    }


def ledger(args) -> None:
    revisions = rule_revisions(Path(args.rules)) if args.rules else None
    out = compute_ledger(args.adjudicated, revisions)
    if args.rules:
        out["rules_sha256"] = digest(Path(args.rules).read_bytes())
    print(
        json.dumps(
            {"digest": write_json(Path(args.out), out), "rules": len(out["rules"])}
        )
    )


def _saved_ledger_problems(saved, evidence, rules_sha256):
    """Describe any mismatch between persisted and recomputed confidence."""
    problems = []
    if saved.get("rules_sha256") != rules_sha256:
        problems.append("saved ledger is bound to a different ruleset")
    if sorted((s["file"], s["sha256"]) for s in saved.get("sources", [])) != sorted(
        (s["file"], s["sha256"]) for s in evidence["sources"]
    ):
        problems.append("saved ledger cites stale or different adjudication receipts")
    if saved.get("rules") != evidence["rules"]:
        problems.append("saved ledger values differ from the recomputed evidence")
    return problems


def check(args) -> int:
    """Recompute confidence from hash-verified adjudications for the exact candidate rules."""
    import yaml

    rules_bytes = Path(args.rules).read_bytes()
    revisions = rule_revisions(Path(args.rules))
    evidence = compute_ledger(args.adjudicated, revisions)
    problems = []
    if args.ledger:
        problems.extend(
            _saved_ledger_problems(
                read_json(Path(args.ledger)), evidence, digest(rules_bytes)
            )
        )
    confidence = evidence["rules"]
    for rule in yaml.safe_load(rules_bytes.decode("utf-8"))["rules"]:
        claimed = rule.get("metadata", {}).get("confidence")
        entry = confidence.get(rule["id"], {})
        tier = entry.get("evidence_tier", "unqualified")
        if claimed == "HIGH" and tier != "default":
            problems.append(
                f"{rule['id']}: claims HIGH confidence but evidence tier is {tier}"
            )
        if tier == "retire":
            problems.append(
                f"{rule['id']}: evidence tier is retire ({entry.get('tp')}/{entry.get('decided')})"
            )
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


# --- Resumable labeling: sealed part receipts -------------------------------
# A long labeling pass is split into disjoint, half-open position ranges of one
# packet. Each finished part is sealed: its labels are written first, then a
# receipt that binds them to the packet, the context supplement, the reviewer
# instructions, the reviewer and the effort. A crash before the receipt leaves
# nothing to trust, so the part is labeled again. Merging recomputes counts
# from the sealed labels and refuses gaps, overlaps and drifted pins.
PART_SCHEMA = "factory.review-part.v1"
PART_PIN_FIELDS = (
    "packet_sha256",
    "context_sha256",
    "instructions_sha256",
    "reviewer",
    "effort",
)


def part_pins(packet_path, context_path, reviewer, effort) -> dict:
    """Current pins; a part sealed under any other value is stale."""
    if not reviewer.strip() or not effort.strip():
        raise SystemExit("reviewer and effort are required pins")
    return {
        "packet_sha256": digest(Path(packet_path).read_bytes()),
        "context_sha256": (
            digest(Path(context_path).read_bytes()) if context_path else None
        ),
        "instructions_sha256": digest(INSTRUCTIONS.encode()),
        "reviewer": reviewer,
        "effort": effort,
    }


def _part_counts(packet: dict, start: int, stop: int, labels: list) -> dict:
    """Every position in [start, stop) answered once, in packet order."""
    items = packet["items"]
    if not (0 <= start < stop <= len(items)):
        raise ValueError(f"range [{start}, {stop}) is outside the packet")
    expected = [item["item"] for item in items[start:stop]]
    if [row.get("item") for row in labels] != expected:
        raise ValueError("part labels do not cover the range in packet order")
    counts = dict.fromkeys(VERDICTS, 0)
    for row in labels:
        if row.get("verdict") not in VERDICTS:
            raise ValueError(f"invalid verdict for {row.get('item')}")
        if not isinstance(row.get("reason"), str) or not row["reason"].strip():
            raise ValueError(f"missing reason for {row['item']}")
        counts[row["verdict"]] += 1
    return {**counts, "positions": stop - start}


def seal_part(args) -> None:
    """Save part labels and publish their hash-bound completion marker last."""
    packet = read_json(Path(args.packet))
    start, stop = args.range
    document = read_json(Path(args.labels))
    labels = [
        {"item": row["item"], "verdict": row["verdict"], "reason": row["reason"]}
        for row in document["labels"]
    ]
    pins = part_pins(args.packet, args.context, args.reviewer, args.effort)
    counts = _part_counts(packet, start, stop, labels)
    root = Path(args.dir)
    name = f"part-{start:05d}-{stop:05d}"
    observations = root / f"{name}.labels.json"
    _atomic_json(observations, {"range": [start, stop], "labels": labels})
    receipt = {
        "schema": PART_SCHEMA,
        "range": [start, stop],
        "state": "COMPLETE",
        "pins": pins,
        "counts": counts,
        "labels": {
            "path": observations.name,
            "sha256": digest(observations.read_bytes()),
        },
    }
    _atomic_json(root / f"{name}.receipt.json", receipt)  # Marker last.
    print(json.dumps({"sealed": name, "counts": counts}))


def _sealed_part_body(root: Path, reference: dict) -> dict:
    """Read bounded label bytes from within the designated part directory."""
    path = (root / relative_path(reference.get("path"))).resolve()
    if path.parent != root.resolve():
        raise ValueError("part labels outside the part directory")
    with path.open("rb") as stream:
        payload = stream.read(MAX_EVIDENCE_BYTES + 1)
    if len(payload) > MAX_EVIDENCE_BYTES or digest(payload) != reference.get("sha256"):
        raise ValueError("part labels digest mismatch")
    return strict_json(payload)


def validate_part(root: Path, receipt: dict, packet: dict, pins: dict) -> list:
    """Fail closed; return the part's labels only when every check holds."""
    if receipt.get("schema") != PART_SCHEMA or receipt.get("state") != "COMPLETE":
        raise ValueError("not a complete part receipt")
    for field in PART_PIN_FIELDS:
        if receipt.get("pins", {}).get(field) != pins[field]:
            raise ValueError(f"pin drift: {field}")
    body = _sealed_part_body(root, receipt.get("labels", {}))
    start, stop = receipt.get("range", [None, None])
    if body.get("range") != [start, stop] or not all(
        type(value) is int for value in (start, stop)
    ):
        raise ValueError("part range mismatch")
    if _part_counts(packet, start, stop, body["labels"]) != receipt.get("counts"):
        raise ValueError("counts disagree with sealed labels")
    return body["labels"]


def reconcile_parts(root: Path, packet: dict, pins: dict):
    """Valid sealed parts by range, the rejected receipts, and uncovered ranges."""
    valid, rejected = {}, {}
    for path in sorted(root.glob("part-*.receipt.json")):
        try:
            receipt = strict_json(path.read_bytes())
            labels = validate_part(root, receipt, packet, pins)
        except (ValueError, OSError, KeyError, TypeError) as exc:
            rejected[path.name] = str(exc)
            continue
        valid[tuple(receipt["range"])] = labels
    missing, cursor = [], 0
    for start, stop in sorted(valid):
        if start < cursor:
            raise SystemExit(f"sealed parts overlap at position {start}")
        if start > cursor:
            missing.append([cursor, start])
        cursor = stop
    if cursor < len(packet["items"]):
        missing.append([cursor, len(packet["items"])])
    return valid, rejected, missing


def merge_parts(args) -> int:
    """Reconcile sealed parts and write labels once every position is covered."""
    packet = read_json(Path(args.packet))
    pins = part_pins(args.packet, args.context, args.reviewer, args.effort)
    root = Path(args.dir)
    valid, rejected, missing = reconcile_parts(root, packet, pins)
    status = {
        "sealed": [list(span) for span in sorted(valid)],
        "rejected": rejected,
        "missing": missing,
    }
    if missing or args.out is None:
        print(json.dumps(status, indent=1))
        return 2 if missing else 0
    labels = [row for span in sorted(valid) for row in valid[span]]
    write_json(
        Path(args.out),
        {
            "reviewer": args.reviewer,
            "effort": args.effort,
            "conditions": args.conditions,
            "packet_sha256": pins["packet_sha256"],
            "parts": [
                {
                    "range": list(span),
                    "receipt_sha256": digest(
                        (
                            root / f"part-{span[0]:05d}-{span[1]:05d}.receipt.json"
                        ).read_bytes()
                    ),
                }
                for span in sorted(valid)
            ],
            "labels": labels,
        },
    )
    print(json.dumps({**status, "out": args.out, "labels": len(labels)}))
    return 0


def review_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Blinded precision packets, adjudication and confidence ledger",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    packet = commands.add_parser("packet")
    packet.add_argument("--alerts", required=True)
    packet.add_argument("--rules", required=True)
    packet.add_argument("--cohort", required=True)
    packet.add_argument("--per-rule", type=int, default=30)
    packet.add_argument("--seed", type=int, required=True)
    packet.add_argument("--out", required=True)
    packet.add_argument("--key", required=True)
    judge = commands.add_parser("judge")
    judge.add_argument("--packet", required=True)
    judge.add_argument("--labels", nargs=2, required=True)
    judge.add_argument("--context")
    judge.add_argument("--out", required=True)
    adjudicated = commands.add_parser("adjudicate")
    adjudicated.add_argument("--packet", required=True)
    adjudicated.add_argument("--key", required=True)
    adjudicated.add_argument("--labels", nargs=2, required=True)
    adjudicated.add_argument("--reviewer", nargs=2, required=True)
    adjudicated.add_argument("--judge")
    adjudicated.add_argument("--judge-packet")
    adjudicated.add_argument("--judge-name")
    adjudicated.add_argument("--context")
    adjudicated.add_argument("--effort-receipt", action="append")
    adjudicated.add_argument("--out", required=True)
    led = commands.add_parser("ledger")
    led.add_argument("--adjudicated", nargs="+", required=True)
    led.add_argument("--rules")
    led.add_argument("--out", required=True)
    checked = commands.add_parser("check")
    checked.add_argument("--adjudicated", nargs="+", required=True)
    checked.add_argument("--rules", required=True)
    checked.add_argument("--ledger")
    for name in ("seal-part", "merge-parts"):
        part = commands.add_parser(name)
        part.add_argument("--packet", required=True)
        part.add_argument("--context")
        part.add_argument("--reviewer", required=True)
        part.add_argument("--effort", required=True)
        part.add_argument("--dir", required=True)
        if name == "seal-part":
            part.add_argument("--labels", required=True)
            part.add_argument("--range", type=int, nargs=2, required=True)
        else:
            part.add_argument("--conditions", default="")
            part.add_argument("--out")
    args = parser.parse_args(argv)
    if args.command == "merge-parts":
        return merge_parts(args)
    handlers = {
        "seal-part": seal_part,
        "packet": build_packet,
        "judge": build_judge,
        "adjudicate": adjudicate,
        "ledger": ledger,
    }
    if args.command == "check":
        return check(args)
    handlers[args.command](args)
    return 0


if __name__ == "__main__":
    commands = {
        "advisory-recall": recall_main,
        "review": review_main,
        "prepare-linked-captures": prepare_captures_main,
    }
    command = commands.get(sys.argv[1]) if len(sys.argv) > 1 else None
    raise SystemExit(command(sys.argv[2:]) if command else main())
