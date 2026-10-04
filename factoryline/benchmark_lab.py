"""Manifest-bound real-defect benchmark evaluation for senior review.

This adapter evaluates results from an external test engine. It never claims to
have generated a defect corpus or executed the replay commands itself.
"""

from __future__ import annotations

import hashlib
import json
import platform
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from importlib.metadata import PackageNotFoundError, version

from .runtime_audit_common import (
    canonical_bytes,
    exact_keys,
    reject_secret_material,
    require_digest,
)


SCHEMA = "factory.defect-benchmark.v1"
CATEGORIES = (
    "stateful_invariant",
    "tenant_isolation",
    "failure_recovery",
    "consumer_compatibility",
    "migration_integrity",
    "performance_regression",
    "test_oracle_strength",
)
CLEAN_FINDING = "NO_FINDING"


class BenchmarkError(ValueError):
    """Stable, fail-closed benchmark contract/result error."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _nonempty(value: object, field: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(c) < 32 for c in value)
    ):
        raise BenchmarkError(
            "E_BENCHMARK_FIELD", f"{field} must be a bounded printable string"
        )
    return value.strip()


def _validate_source(source: object) -> str:
    value = _nonempty(source, "case.source", 512)
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        raise BenchmarkError(
            "E_BENCHMARK_SOURCE",
            "source must be a reviewed local identifier, not a URL",
        )
    return value


def _argv(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise BenchmarkError(
            "E_BENCHMARK_REPLAY", f"{field} must contain 1..32 arguments"
        )
    result = []
    for index, item in enumerate(value):
        result.append(_nonempty(item, f"{field}[{index}]", 256))
    return result


def _validate_case(case: object, index: int, seen: set[str]) -> dict[str, Any]:
    if not isinstance(case, dict):
        raise BenchmarkError("E_BENCHMARK_CONTRACT", f"case {index} must be an object")
    try:
        exact_keys(
            case,
            {
                "id",
                "category",
                "source",
                "source_sha256",
                "expected_finding",
                "replay_argv",
                "buggy_sha256",
                "fixed_sha256",
            },
        )
    except Exception as exc:
        raise BenchmarkError("E_BENCHMARK_CONTRACT", f"case {index}: {exc}") from exc
    case_id = _nonempty(case.get("id"), f"case[{index}].id", 160)
    if case_id in seen:
        raise BenchmarkError("E_BENCHMARK_CONTRACT", f"duplicate case id: {case_id}")
    seen.add(case_id)
    category = case.get("category")
    if category not in CATEGORIES:
        raise BenchmarkError(
            "E_BENCHMARK_CATEGORY", f"unsupported category for {case_id}"
        )
    return {
        "id": case_id,
        "category": category,
        "source": _validate_source(case.get("source")),
        "source_sha256": require_digest(
            case.get("source_sha256"), f"case[{index}].source_sha256"
        ),
        "expected_finding": _nonempty(
            case.get("expected_finding"), f"case[{index}].expected_finding", 512
        ),
        "replay_argv": _argv(case.get("replay_argv"), f"case[{index}].replay_argv"),
        "buggy_sha256": require_digest(
            case.get("buggy_sha256"), f"case[{index}].buggy_sha256"
        ),
        "fixed_sha256": require_digest(
            case.get("fixed_sha256"), f"case[{index}].fixed_sha256"
        ),
    }


def validate_benchmark_manifest(value: dict[str, Any]) -> dict[str, Any]:
    """Validate a complete immutable benchmark manifest and normalize strings."""
    if not isinstance(value, dict):
        raise BenchmarkError("E_BENCHMARK_CONTRACT", "manifest must be an object")
    reject_secret_material(value, path="benchmark")
    try:
        exact_keys(value, {"schema", "benchmark_id", "version", "cases"})
    except Exception as exc:
        raise BenchmarkError("E_BENCHMARK_CONTRACT", str(exc)) from exc
    if value.get("schema") != SCHEMA:
        raise BenchmarkError("E_BENCHMARK_CONTRACT", f"schema must be {SCHEMA}")
    cases = value.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 500:
        raise BenchmarkError(
            "E_BENCHMARK_CONTRACT", "cases must contain 1..500 entries"
        )
    seen: set[str] = set()
    return {
        "schema": SCHEMA,
        "benchmark_id": _nonempty(value.get("benchmark_id"), "benchmark_id", 160),
        "version": _nonempty(value.get("version"), "version", 40),
        "cases": [
            _validate_case(case, index, seen) for index, case in enumerate(cases)
        ],
    }


def _observation(value: object, case_id: str, side: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError(
            "E_BENCHMARK_RESULT", f"{case_id}.{side} must be an object"
        )
    try:
        exact_keys(value, {"state", "finding"})
    except Exception as exc:
        raise BenchmarkError("E_BENCHMARK_RESULT", f"{case_id}.{side}: {exc}") from exc
    state = value.get("state")
    if state not in {"PASS", "FAIL"}:
        raise BenchmarkError(
            "E_BENCHMARK_RESULT", f"{case_id}.{side}.state must be PASS or FAIL"
        )
    finding = value.get("finding")
    if (
        not isinstance(finding, str)
        or len(finding) > 512
        or any(ord(c) < 32 for c in finding)
    ):
        raise BenchmarkError(
            "E_BENCHMARK_RESULT",
            f"{case_id}.{side}.finding must be a bounded printable string",
        )
    return {"state": state, "finding": finding.strip()}


def _evaluate_case(
    case: dict[str, Any], pair: object, totals: dict[str, dict[str, int]]
) -> dict[str, Any]:
    if not isinstance(pair, dict):
        raise BenchmarkError(
            "E_BENCHMARK_RESULT", f"{case['id']} observation must be an object"
        )
    try:
        exact_keys(pair, {"buggy", "fixed"})
    except Exception as exc:
        raise BenchmarkError("E_BENCHMARK_RESULT", f"{case['id']}: {exc}") from exc
    buggy = _observation(pair["buggy"], case["id"], "buggy")
    fixed = _observation(pair["fixed"], case["id"], "fixed")
    clean = case["expected_finding"] == CLEAN_FINDING
    buggy_correct = (
        buggy["state"] == "PASS" and buggy["finding"] in {"", CLEAN_FINDING}
        if clean
        else buggy["state"] == "FAIL" and buggy["finding"] == case["expected_finding"]
    )
    fixed_correct = fixed["state"] == "PASS" and fixed["finding"] in {"", CLEAN_FINDING}
    correct = buggy_correct and fixed_correct
    metric = totals[case["category"]]
    metric.update(
        cases=metric["cases"] + 1, correct_cases=metric["correct_cases"] + int(correct)
    )
    key = "tn" if clean else "tp"
    metric[key] += int(buggy_correct)
    metric["fp" if clean else "fn"] += int(not buggy_correct)
    return {
        "id": case["id"],
        "category": case["category"],
        "expected_finding": case["expected_finding"],
        "buggy": buggy,
        "fixed": fixed,
        "buggy_correct": buggy_correct,
        "fixed_correct": fixed_correct,
        "correct": correct,
        "replay_argv": case["replay_argv"],
    }


def _metrics(totals: dict[str, dict[str, int]]) -> dict[str, Any]:
    result = {}
    for category, metric in totals.items():
        recall_den = metric["tp"] + metric["fn"]
        precision_den = metric["tp"] + metric["fp"]
        result[category] = {
            **metric,
            "recall": metric["tp"] / recall_den if recall_den else None,
            "precision": metric["tp"] / precision_den if precision_den else None,
        }
    return result


def evaluate_benchmark(
    manifest: dict[str, Any], observations: dict[str, Any], *, out: Path | None = None
) -> dict[str, Any]:
    """Evaluate externally collected buggy/fixed observations with exact metrics."""
    contract = validate_benchmark_manifest(manifest)
    if not isinstance(observations, dict):
        raise BenchmarkError(
            "E_BENCHMARK_RESULT", "observations must be an object keyed by case id"
        )
    expected_ids = {case["id"] for case in contract["cases"]}
    if set(observations) != expected_ids:
        missing = sorted(expected_ids - set(observations))
        extra = sorted(set(observations) - expected_ids)
        raise BenchmarkError(
            "E_BENCHMARK_RESULT",
            f"case observations differ; missing={missing}, extra={extra}",
        )
    rows = []
    totals = {
        category: {"cases": 0, "correct_cases": 0, "tp": 0, "fn": 0, "tn": 0, "fp": 0}
        for category in CATEGORIES
    }
    rows = [
        _evaluate_case(case, observations[case["id"]], totals)
        for case in contract["cases"]
    ]
    metrics = _metrics(totals)
    core = {
        "schema": "factory.defect-benchmark-receipt.v1",
        "marker": "DEFECT_BENCHMARK_BOUND",
        "benchmark": contract,
        "cases": rows,
        "metrics": metrics,
        "decision": "PASS" if all(row["correct"] for row in rows) else "BLOCKED",
        "authority": "none",
        "release_approval": False,
        "claim_boundary": "Evaluates supplied replay observations; does not execute commands or prove production readiness.",
    }
    receipt = {
        **core,
        "receipt_sha256": hashlib.sha256(canonical_bytes(core)).hexdigest(),
    }
    if out is not None:
        destination = Path(out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_bytes(receipt) + b"\n")
    return receipt


def load_benchmark_json(path: Path) -> dict[str, Any]:
    """Load one bounded benchmark JSON object for a review-only CLI input."""
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkError("E_BENCHMARK_JSON", str(exc)) from exc
    if not isinstance(value, dict):
        raise BenchmarkError("E_BENCHMARK_JSON", "JSON must be an object")
    return value


def _wilson(successes: int, trials: int) -> list[float] | None:
    """Return a two-sided 95% Wilson interval, or None without observations."""
    if not trials:
        return None
    z = 1.96
    p = successes / trials
    d = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / d
    radius = z * ((p * (1 - p) / trials + z * z / (4 * trials * trials)) ** 0.5) / d
    return [round(max(0, center - radius), 6), round(min(1, center + radius), 6)]


def _public_cases(corpus: Path, payload: bytes | None = None) -> tuple[dict, list]:
    try:
        raw = payload if payload is not None else corpus.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkError("E_BENCHMARK_CORPUS", str(exc)) from exc
    cases = data.get("cases") if isinstance(data, dict) else None
    if not isinstance(cases, list) or not cases:
        raise BenchmarkError("E_BENCHMARK_CORPUS", "corpus requires cases")
    return data, cases


def _public_case(case: object, index: int) -> tuple[str, str]:
    if not isinstance(case, dict) or case.get("category") not in CATEGORIES:
        raise BenchmarkError("E_BENCHMARK_CORPUS", f"invalid case {index}")
    cid = case.get("id")
    if not isinstance(cid, str) or not cid:
        raise BenchmarkError("E_BENCHMARK_CORPUS", f"invalid case id {index}")
    if not all(
        isinstance(case.get(key), str)
        for key in ("source", "fixed_source", "expected_finding")
    ):
        raise BenchmarkError("E_BENCHMARK_CORPUS", f"invalid source in case {index}")
    return cid, case["category"]


def _public_pair(
    root: Path, case: dict, index: int, scanner
) -> tuple[list, list, list]:
    observed, hashes, sources = [], [], []
    for label, source in (("buggy", case["source"]), ("fixed", case["fixed_source"])):
        path = root / f"{index}-{label}.py"
        path.write_text(source, encoding="utf-8")
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        hashes.append(digest)
        result = scanner(root)
        observed.append(
            sorted({f["code"] for f in result["findings"] if f["path"] == path.name})
        )
        sources.append({"case": case["id"], "side": label, "sha256": digest})
    return observed, hashes, sources


def _public_metrics(counts: dict[str, int]) -> dict[str, Any]:
    rden, pden = counts["tp"] + counts["fn"], counts["tp"] + counts["fp"]
    return {
        **counts,
        "n_positive": rden,
        "n_predicted_positive": pden,
        "n_negative": counts["tn"] + counts["fp"],
        "recall": counts["tp"] / rden if rden else None,
        "recall_ci95_wilson": _wilson(counts["tp"], rden),
        "precision": counts["tp"] / pden if pden else None,
        "precision_ci95_wilson": _wilson(counts["tp"], pden),
    }


def _public_observations(cases: list, totals: dict) -> tuple[list, list]:
    from functools import partial
    from .review_audits import security_scan

    rows, sources = [], []
    # A tenant boundary is a declared requirement, not something inferred from
    # a method name. Apply one fixed contract to every buggy and clean input;
    # the scanner never receives a case label or its expected finding.
    scanner = partial(security_scan, tenant_read_calls=("db.get",))
    with tempfile.TemporaryDirectory(prefix="factory-public-benchmark-") as tmp:
        for index, case in enumerate(cases):
            cid, cat = _public_case(case, index)
            pair, hashes, bindings = _public_pair(Path(tmp), case, index, scanner)
            sources.extend(bindings)
            clean = case["expected_finding"] == CLEAN_FINDING
            detected = not pair[0] if clean else case["expected_finding"] in pair[0]
            key = (
                ("tn" if detected else "fp") if clean else ("tp" if detected else "fn")
            )
            totals[cat][key] += 1
            rows.append(
                {
                    "id": cid,
                    "category": cat,
                    "expected_finding": case["expected_finding"],
                    "buggy_findings": pair[0],
                    "fixed_findings": pair[1],
                    "buggy_correct": detected,
                    "fixed_clean": not pair[1],
                    "buggy_sha256": hashes[0],
                    "fixed_sha256": hashes[1],
                }
            )
    return rows, sources


def _public_agent_actions(
    rows: list[dict[str, Any]], corpus_sha256: str
) -> list[dict[str, Any]]:
    actions = []
    for row in rows:
        if row["buggy_correct"] and row["fixed_clean"]:
            continue
        miss_kind = (
            "false negative"
            if not row["buggy_correct"]
            else "fixed-case false positive"
        )
        high_risk = row["category"] in {"tenant_isolation", "test_oracle_strength"}
        actions.append(
            {
                "id": f"benchmark-{row['id']}",
                "priority": "P1" if high_risk else "P2",
                "agent_role": "specialty_ai_security_reviewer"
                if row["category"] in {"tenant_isolation", "stateful_invariant"}
                else "specialty_ai_test_reviewer",
                "category": row["category"],
                "action": f"Investigate the measured {miss_kind} for seeded case {row['id']}; improve detection or reduce the false alarm without changing the public case labels.",
                "evidence_to_attach": "Candidate scanner rule/source hash, case and corpus hashes, observed finding codes, and a rerun receipt showing buggy/fixed discrimination.",
                "case_sha256": row["buggy_sha256"],
                "corpus_sha256": corpus_sha256,
                "stop_condition": "Keep the benchmark BLOCKED while a required seeded case is missed or a fixed control is falsely flagged.",
            }
        )
    return actions


def run_public_benchmark(corpus: Path | None = None) -> dict[str, Any]:
    """Run the seeded public corpus through review_audits.security_scan.

    Corpus truth is hand-labeled and public. The isolated source snippets are
    temporary inputs; the production scanner is the only observation engine.
    """
    corpus = corpus or Path(__file__).parent / "data" / "public_defect_corpus.json"
    corpus_bytes = Path(corpus).read_bytes()
    corpus_sha256 = hashlib.sha256(corpus_bytes).hexdigest()
    data, cases = _public_cases(Path(corpus), corpus_bytes)
    totals = {c: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for c in CATEGORIES}
    rows, sources = _public_observations(cases, totals)
    metrics = {cat: _public_metrics(counts) for cat, counts in totals.items()}
    overall = {
        key: sum(m[key] for m in totals.values()) for key in ("tp", "fp", "tn", "fn")
    }
    metrics["overall"] = _public_metrics(overall)
    measured_unsupported_behaviors = {
        category: {
            "state": "MEASURED",
            "positive_cases": metrics[category]["n_positive"],
            "true_positives": metrics[category]["tp"],
            "false_negatives": metrics[category]["fn"],
            "recall": metrics[category]["recall"],
            "recall_ci95_wilson": metrics[category]["recall_ci95_wilson"],
        }
        for category in ("tenant_isolation", "test_oracle_strength")
    }
    agent_actions = _public_agent_actions(rows, corpus_sha256)
    try:
        package_version = version("factoryline-code-factory")
    except PackageNotFoundError:
        package_version = "source-checkout"
    core = {
        "schema": "factory.public-seeded-benchmark.v1",
        "marker": "PUBLIC_SEEDED_BENCHMARK",
        "benchmark_id": data.get("benchmark_id"),
        "version": data.get("version"),
        "scanner": "factoryline.review_audits.security_scan",
        "scanner_contract": {
            "tenant_read_calls": ["db.get"],
            "tenant_keyword": "tenant_id",
        },
        "scanner_version": package_version,
        "scanner_sources": [
            {
                "path": name,
                "sha256": hashlib.sha256(
                    (Path(__file__).parent / name).read_bytes()
                ).hexdigest(),
            }
            for name in ("review_audits.py", "benchmark_lab.py")
        ],
        "python": platform.python_version(),
        "platform": platform.platform(),
        "corpus_sha256": corpus_sha256,
        "source_bindings": sources,
        "cases": rows,
        "metrics": metrics,
        "measured_unsupported_behaviors": measured_unsupported_behaviors,
        "agent_actions": agent_actions,
        "decision": "PASS"
        if all(r["buggy_correct"] and r["fixed_clean"] for r in rows)
        else "BLOCKED",
        "authority": "none",
        "release_approval": False,
        "claim_boundary": "Public hand-labeled seeded Python AST corpus with one declared db.get tenant-read contract applied uniformly to all inputs; not independently held out, AI-written, representative, runtime, or production evidence. Static keyword presence does not authenticate tenants; mutation and cross-tenant runtime checks remain separate. Tenant-isolation and test-oracle-strength cases have explicit per-category confusion counts; a measured miss is a false negative, not coverage.",
    }
    core["receipt_sha256"] = hashlib.sha256(canonical_bytes(core)).hexdigest()
    return core


def main() -> int:
    """Print a measured run of the built-in public seeded corpus."""
    print(json.dumps(run_public_benchmark(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
