"""Verify the factory-level advisory recall record and optionally replay its pattern lane.

The record binds each advisory to its fix and pre-fix revisions, pre-fix file
digests, fix hunks and every individual detection. This script recomputes the
summary from those observations and rejects any mismatch. With --prefix-cache
it checks the pre-fix bytes; with --opengrep it re-runs the bound pattern
ruleset on them and requires identical detections. CodeQL results are not
replayed here: rerun the bound argv on each source_revision for that.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from factoryline.benchmark_lab import _wilson
from factoryline.deep_audit_io import strict_json

SCHEMA = "factory.advisory-recall-factory.v2"
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
_SHA256 = re.compile(r"[0-9a-f]{64}")


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
        if item["parent"] not in parents or not _SHA256.fullmatch(item["sha256"]):
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


def summarize(record: dict) -> dict:
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


def verify(record: dict) -> dict:
    if record.get("schema") != SCHEMA:
        raise ValueError("unexpected record schema")
    pattern = record["candidate"]["pattern_lane"]
    codeql = record["candidate"]["codeql_lane"]
    for value in (
        pattern["ruleset_sha256"],
        pattern["opengrep_binary_sha256"],
        codeql["bundle_sha256"],
        codeql["query_sets_sha256"],
    ):
        if not _SHA256.fullmatch(value):
            raise ValueError("unbound tool, ruleset or query digest")
    names = [case["ghsa"] for case in record["cases"]]
    if len(names) != len(set(names)):
        raise ValueError("duplicate advisory")
    for case in record["cases"]:
        _validate_case(case)
    summary = summarize(record)
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
            if hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError(
                    f"{case['ghsa']}: pre-fix bytes differ for {item['path']}"
                )
    return sum(len(case["prefix_files"]) for case in record["cases"])


def replay_pattern(record: dict, cache: Path, opengrep: str, ruleset: Path) -> None:
    import yaml

    if (
        hashlib.sha256(ruleset.read_bytes()).hexdigest()
        != (record["candidate"]["pattern_lane"]["ruleset_sha256"])
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
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
        summary = verify(record)
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


if __name__ == "__main__":
    raise SystemExit(main())
