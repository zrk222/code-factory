"""Counterfactual integrity challenge for Factoryline proof verification."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json
import tempfile

from .proof import load_trace, verify_trace


def challenge_trace(trace_path: Path, root: Path | None = None) -> dict:
    trace_path = Path(trace_path)
    trace = load_trace(trace_path)
    baseline = verify_trace(trace_path, root=root)
    mutations = []
    variants = []

    empty = deepcopy(trace)
    empty["nodes"] = []
    variants.append(("empty_trace", empty))

    bad_hash = deepcopy(trace)
    if bad_hash.get("nodes"):
        bad_hash["nodes"][0]["receipt_sha256"] = "0" * 64
    variants.append(("receipt_hash_tamper", bad_hash))

    if len(trace.get("nodes", [])) > 1:
        reordered = deepcopy(trace)
        reordered["nodes"] = list(reversed(reordered["nodes"]))
        variants.append(("stage_reorder", reordered))

    with tempfile.TemporaryDirectory(prefix="factory-challenge-") as temp:
        for name, variant in variants:
            path = Path(temp) / f"{name}.json"
            path.write_text(json.dumps(variant, indent=2), encoding="utf-8")
            result = verify_trace(path, root=root)
            mutations.append({
                "unit": name,
                "killed": not result["valid"],
                "evidence": "; ".join(result["errors"]) if result["errors"] else "mutant incorrectly verified",
            })
    killed = sum(bool(item["killed"]) for item in mutations)
    return {
        "schema": "factory.challenge.v1",
        "brick": "factoryline",
        "feature": trace.get("feature"),
        "stage": "proof_integrity_counterfactual",
        "passed": baseline["valid"] and killed == len(mutations),
        "mutants_total": len(mutations),
        "mutants_killed": killed,
        "mutations": mutations,
    }
