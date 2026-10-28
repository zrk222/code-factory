"""Run hash-bound startup checks for every cohort arm before permitting launch."""

from __future__ import annotations

import argparse
import ast
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess
import sys

SCHEMA = "factory.precision-cohort-startup.v1"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def bound_path(root, relative):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe captured path")
    selected = (root / path).resolve()
    if not selected.is_relative_to(root.resolve()):
        raise ValueError("captured path escapes root")
    return selected


def startup(scanner, workspace, profile, expected_files):
    """Read source/config through the frozen API; never execute target modules."""
    if platform.python_version() != profile["python"] or sys.flags.optimize:
        raise ValueError("interpreter differs from registered profile")
    for name, version in profile["dependencies"].items():
        if importlib.metadata.version(name) != version:
            raise ValueError("dependency differs from registered profile: " + name)
    scanner = Path(scanner).resolve()
    sys.path.insert(0, str(scanner))
    from factoryline import cli, review_audits as audit

    if not Path(cli.__file__).resolve().is_relative_to(scanner):
        raise ValueError("frozen scanner import identity mismatch")
    workspace = Path(workspace).resolve()
    files = audit._security_source_files(workspace)
    if {p.relative_to(workspace).as_posix() for p in files} != set(expected_files):
        raise ValueError("source inventory differs from registered capture")
    if len(files) > audit._validate_source_file_limit(None):
        raise ValueError("source inventory exceeds scanner capacity")
    for path in files:
        relative = path.relative_to(workspace).as_posix()
        try:
            ast.parse(audit._security_source_bytes(workspace, relative), filename=relative)
        except (SyntaxError, ValueError, RecursionError) as error:
            raise ValueError("unsupported captured Python syntax: " + relative) from error
    _, collection = audit._pytest_collection_config(
        workspace, files, allow_unknown=profile["security_only"] is True
    )
    return {"state": "PASS", "files": len(files), "collection": collection}


def scanner_bundles(root, protocol, bindings):
    scanners = {}
    for arm in ("baseline", "candidate"):
        bundle = bound_path(root, protocol["scanner"][arm])
        manifest = bundle / "manifest.json"
        if digest(manifest) != protocol["scanner"][arm + "_manifest_sha256"]:
            raise ValueError("scanner manifest seal changed")
        bindings[str(manifest)] = digest(manifest)
        for name, expected in json.loads(manifest.read_text()).items():
            path = bound_path(bundle / "scanner", name)
            if digest(path) != expected:
                raise ValueError("frozen scanner source changed")
            bindings[str(path)] = expected
        scanners[arm] = bundle / "scanner"
    return scanners


def inputs(study):
    study = Path(study).resolve()
    root = study.parents[1]
    registration = study / "registration.json"
    protocol = json.loads(registration.read_text(encoding="utf-8-sig"))
    if digest(registration) != (study / "registration.sha256").read_text().strip():
        raise ValueError("registration seal mismatch")
    capture = study / "source-capture.json"
    rows = json.loads(capture.read_text(encoding="utf-8-sig"))["repositories"]
    bindings = {
        str(registration): digest(registration),
        str(capture): digest(capture),
        str(Path(__file__).resolve()): digest(__file__),
    }
    controller = study / "study.py"
    if digest(controller) != protocol["controllers"]["study.py"]:
        raise ValueError("registered run controller changed")
    bindings[str(controller)] = digest(controller)
    scanners = scanner_bundles(root, protocol, bindings)
    jobs = []
    for row in rows:
        if row["state"] != "CAPTURED":
            continue
        source = bound_path(root, row["source_root"])
        if not source.is_relative_to(study / "capture"):
            raise ValueError("unexpected cohort source root")
        for item in row["sources"]:
            path = bound_path(source, item["path"])
            if digest(path) != item["sha256"]:
                raise ValueError("captured source/configuration changed")
            bindings[str(path)] = item["sha256"]
        expected = [item["path"] for item in row["sources"] if item["kind"] == "python"]
        for arm, scanner in scanners.items():
            jobs.append(
                {
                    "repository": row["repository"],
                    "arm": arm,
                    "scanner": str(scanner),
                    "workspace": str(source),
                    "profile": protocol["scanner"]["profile"],
                    "expected_files": expected,
                }
            )
    identities = [(r["repository"], r["arm"]) for r in jobs]
    if not identities or len(set(identities)) != len(identities):
        raise ValueError("empty or duplicate cohort identities")
    return jobs, bindings, controller


def worker(job):
    try:
        command = [
            sys.executable,
            "-B",
            str(Path(__file__).resolve()),
            "--worker",
            json.dumps(job),
        ]
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=90, check=False
        )
        observation = (
            json.loads(result.stdout)
            if result.returncode == 0 and not result.stderr
            else {
                "state": "BLOCKED",
                "error": result.stderr.strip() or result.stdout.strip(),
            }
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        observation = {
            "state": "BLOCKED",
            "error": type(error).__name__ + ": " + str(error),
        }
    return {"repository": job["repository"], "arm": job["arm"], **observation}


def preflight(study):
    jobs, bindings, controller, checks = [], {}, None, []
    unchanged, error = False, None
    try:
        jobs, bindings, controller = inputs(study)
        with ThreadPoolExecutor(max_workers=2) as pool:
            checks = list(pool.map(worker, jobs))
        unchanged = all(digest(path) == expected for path, expected in bindings.items())
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        error = type(exc).__name__ + ": " + str(exc)
    receipt = {
        "schema": SCHEMA,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "state": "PASS"
        if not error
        and unchanged
        and checks
        and all(r["state"] == "PASS" for r in checks)
        else "BLOCKED",
        "study": str(Path(study).resolve()),
        "controller": str(controller),
        "expected": [[r["repository"], r["arm"]] for r in jobs],
        "inputs": bindings,
        "checks": checks,
        "inputs_unchanged": unchanged,
        "error": error,
        "boundary": "Static startup readiness only; no predictions, precision, complete audit or release claim.",
    }
    receipt["receipt_sha256"] = canonical(receipt)
    return receipt


def validate(receipt):
    if receipt.get("schema") != SCHEMA or receipt.get("state") != "PASS":
        raise ValueError("cohort startup preflight has not passed")
    core = {k: v for k, v in receipt.items() if k != "receipt_sha256"}
    if receipt.get("receipt_sha256") != canonical(core):
        raise ValueError("preflight receipt seal mismatch")
    jobs, bindings, controller = inputs(receipt["study"])
    identities = [[row["repository"], row["arm"]] for row in jobs]
    observed = [[row["repository"], row["arm"]] for row in receipt["checks"]]
    if receipt["expected"] != identities or observed != identities:
        raise ValueError("missing, duplicate or unexpected startup check")
    if receipt["inputs"] != bindings or receipt["controller"] != str(controller):
        raise ValueError("stale startup receipt")
    if receipt["inputs_unchanged"] is not True or any(
        r["state"] != "PASS" for r in receipt["checks"]
    ):
        raise ValueError("failed startup check")
    current = preflight(receipt["study"])
    if current["state"] != "PASS" or any(
        current[key] != receipt[key]
        for key in ("expected", "inputs", "checks", "controller")
    ):
        raise ValueError("startup inputs, inventory or execution profile changed")
    return controller


def launch(receipt):
    controller = validate(receipt)
    return subprocess.run(
        [sys.executable, "-B", str(controller), "run"],
        cwd=controller.parents[2],
        check=False,
    ).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker")
    parser.add_argument("--study", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--launch", action="store_true")
    args = parser.parse_args()
    if args.worker:
        job = json.loads(args.worker)
        try:
            print(
                json.dumps(
                    startup(
                        job["scanner"],
                        job["workspace"],
                        job["profile"],
                        job["expected_files"],
                    )
                )
            )
            return 0
        except Exception as error:
            print(type(error).__name__ + ": " + str(error), file=sys.stderr)
            return 2
    if args.study is None or args.receipt is None:
        parser.error("--study and --receipt are required")
    if args.launch:
        receipt = json.loads(args.receipt.read_text())
        if receipt.get("study") != str(args.study.resolve()):
            raise ValueError("receipt belongs to another study")
        return launch(receipt)
    receipt = preflight(args.study)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    with args.receipt.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            {
                "state": receipt["state"],
                "checks": len(receipt["checks"]),
                "blocked": [r for r in receipt["checks"] if r["state"] != "PASS"],
            }
        )
    )
    return 0 if receipt["state"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
