"""Paired repeat-run benchmark for Code Factory and Prestige optimizations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable


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
    parser = argparse.ArgumentParser(description=__doc__)
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
            1
            for term in terms
            if re.search(rf"\b{re.escape(term.lower())}\b", text)
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
                (
                    candidate["median_ms"] / baseline["median_ms"] - 1
                )
                * 100,
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
