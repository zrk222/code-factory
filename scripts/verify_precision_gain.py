"""Check paired, fixed-panel actionable gain; never certify held-out freshness.

Inputs are hash-bound observations, not aggregate scores. This checks their
internal consistency; source execution and label provenance require review.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from factoryline.benchmark_lab import _wilson

SCHEMA = "factory.precision-gain.v1"
FIELDS = ("raw", "active", "review", "supported")


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _hash(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _index(rows: list[dict]) -> dict[str, dict]:
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("claims must be an array of objects")
    result = {}
    for row in rows:
        key = row.get("id")
        if not isinstance(key, str) or not key or key in result:
            raise ValueError("missing or duplicate claim identity")
        result[key] = row
    if not result:
        raise ValueError("empty cohort")
    return result


def _metrics(rows: dict, labels: dict, population: str) -> dict:
    counts = Counter(labels[key]["label"] for key, row in rows.items() if _member(row, population))
    tp, fp, unclear = (counts[name] for name in ("TP", "FP", "UNCLEAR"))
    decided = tp + fp
    return {
        "TP": tp, "FP": fp, "UNCLEAR": unclear, "decided": decided,
        "precision": tp / decided if decided else None,
        "unclear_inclusive_rate": tp / (decided + unclear) if decided + unclear else None,
        "wilson_95": _wilson(tp, decided),
    }


def _member(row: dict, field: str) -> bool:
    return row["active"] or row["review"] if field == "active_or_review" else row[field]


def _version_rows(name: str, version: dict, contract: dict, labels: dict) -> tuple[dict, list]:
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


def evaluate(contract: dict, baseline: dict, candidate: dict) -> dict:
    """Reject omitted coverage, changed premises, lost TPs and unsupported gains."""
    if not isinstance(contract, dict) or contract.get("schema") != SCHEMA or contract.get("scope") != "fixed_panel":
        raise ValueError("require a fixed-panel contract")
    labels = _index(contract["cases"])
    if any(row.get("label") not in {"TP", "FP", "UNCLEAR"}
           or not _hash(row.get("source_sha256")) for row in labels.values()):
        raise ValueError("invalid source digest or actionable label")
    label_hash = digest(json.dumps(contract["cases"], sort_keys=True, separators=(",", ":")).encode())
    if contract.get("labels_sha256") != label_hash:
        raise ValueError("label seal mismatch")
    if not all(_hash(contract.get(key)) for key in ("context_sha256", "assumptions_sha256")) or not contract.get("policy"):
        raise ValueError("missing context, assumptions or policy")
    reasons, versions = [], []
    for name, version in (("baseline", baseline), ("candidate", candidate)):
        rows, incomplete = _version_rows(name, version, contract, labels)
        reasons.extend(incomplete)
        versions.append(rows)
    before, after = versions
    changed = {key: {"before": [f for f in FIELDS if before[key][f]],
                     "after": [f for f in FIELDS if after[key][f]]}
               for key in labels if any(before[key][f] != after[key][f] for f in FIELDS)}
    if changed != contract.get("expected_changes"):
        reasons.append("observed changes differ from the registered repair impact")
    lost = {field: [key for key in labels if labels[key]["label"] == "TP"
                    and _member(before[key], field) and not _member(after[key], field)]
            for field in ("raw", "active", "supported", "active_or_review")}
    if any(lost.values()):
        reasons.append("true-positive retention failed")
    lost_unclear = {field: [key for key in labels if labels[key]["label"] == "UNCLEAR"
                           and _member(before[key], field) and not _member(after[key], field)]
                    for field in ("raw", "active_or_review")}
    if any(lost_unclear.values()):
        reasons.append("unresolved claims were removed from review")
    metrics = {name: {field: _metrics(rows, labels, field) for field in (*FIELDS, "active_or_review")}
               for name, rows in (("baseline", before), ("candidate", after))}
    old, new = (metrics[name]["active"]["precision"] for name in ("baseline", "candidate"))
    gain = new - old if old is not None and new is not None else None
    state = "BLOCKED" if reasons else "ACTIVE_PRECISION_GAIN_FIXED_PANEL" if gain and gain > 0 else "NO_PRECISION_GAIN"
    selection = any(not before[key]["review"] and after[key]["review"] for key in labels)
    return {
        "schema": SCHEMA, "state": state, "reasons": reasons, "metrics": metrics,
        "active_precision_delta": gain, "changed_claims": changed, "lost_TPs": lost,
        "lost_unclear": lost_unclear,
        "change_kind": "SELECTION_WITH_ABSTENTION" if selection else "ACTIVE_OUTPUT_CHANGE",
        "scope": "fixed_panel", "registered_claims": len(labels),
        "unlabelled_outputs": {name: value["unlabelled_outputs"]
                               for name, value in (("baseline", baseline), ("candidate", candidate))},
        "publication_eligible": False,
        "claim_boundary": "Paired supplied observations only; no proof of fresh sampling, label independence, execution truth or whole-scanner precision.",
    }


def _read_bound(root: Path, reference: dict) -> dict:
    if not isinstance(reference, dict) or not isinstance(reference.get("path"), str):
        raise ValueError("invalid evidence reference")
    path = (root / reference["path"]).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("evidence path escapes contract root")
    payload = path.read_bytes()
    if digest(payload) != reference["sha256"]:
        raise ValueError("evidence digest mismatch")
    return json.loads(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        payload = args.contract.read_bytes()
        contract = json.loads(payload)
        if not isinstance(contract, dict):
            raise ValueError("contract must be an object")
        result = evaluate(contract, _read_bound(args.contract.parent, contract["baseline"]),
                          _read_bound(args.contract.parent, contract["candidate"]))
        result["contract_sha256"] = digest(payload)
        result["evidence"] = {key: contract[key] for key in ("baseline", "candidate")}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {"schema": SCHEMA, "state": "INVALID", "reason": str(exc)}
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"state": result["state"], "out": str(args.out)}))
    return 0 if result["state"] == "ACTIVE_PRECISION_GAIN_FIXED_PANEL" else 2


if __name__ == "__main__":
    raise SystemExit(main())
