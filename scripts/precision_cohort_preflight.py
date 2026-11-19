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
NORMAL_OPERATOR_CONTROLS = (
    ".factory/native-worker-config.json",
    ".factory/operator/manifest.json",
    ".factory/operator/authorization.json",
    ".factory/operator/trust.json",
)


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


def _normal_profile(profile):
    if not isinstance(profile, dict) or profile.get("endpoint") not in (
        None,
        "factory.scan.normal.v1",
    ):
        raise ValueError("unknown startup endpoint profile")
    normal = profile.get("endpoint") == "factory.scan.normal.v1"
    if normal and profile.get("security_only") is not False:
        raise ValueError("normal endpoint requires security_only=False")
    return normal


def _input_file(root, relative, normal):
    if normal:
        from factoryline.deep_audit_io import local_file

        return local_file(root, relative)
    return bound_path(root, relative)


def normal_registered_inputs(workspace, expected_files):
    """Check the complete registered capacity/control metadata before input bytes."""
    from factoryline.deep_audit_io import local_file, relative_path
    from factoryline.runtime_audit_common import require_digest

    if not isinstance(expected_files, list) or not 1 <= len(expected_files) <= 200:
        raise ValueError("normal capture exceeds registered source inventory capacity")
    expected, total = {}, 0
    for row in expected_files:
        name = relative_path(row["path"])
        value = require_digest(row["sha256"], "registered source_sha256")
        if name in expected:
            raise ValueError("duplicate registered input")
        total += local_file(workspace, name).stat().st_size
        if total > 16 * 1024 * 1024:
            raise ValueError("normal capture exceeds 16MiB aggregate input budget")
        expected[name] = value
    for name in NORMAL_OPERATOR_CONTROLS:
        path = workspace / name
        if (path.is_symlink() or path.exists()) and name not in expected:
            raise ValueError("unregistered normal operator control: " + name)
    return expected


def _normal_inventory(workspace, expected_files):
    from factoryline.deep_audit_io import (
        _generated_factory_path,
        _git_paths,
        _source_bytes,
        inventory_candidate,
    )

    expected = normal_registered_inputs(workspace, expected_files)
    product = {
        name: value
        for name, value in expected.items()
        if not _generated_factory_path(name)
    }
    if set(_git_paths(workspace)) != set(product):
        raise ValueError(
            "normal inventory differs from registered source/configuration"
        )
    for name, value in expected.items():
        if _generated_factory_path(name):
            raw, _ = _source_bytes(workspace, name)
            if hashlib.sha256(raw).hexdigest() != value:
                raise ValueError("registered operator control changed")
    inventory = inventory_candidate(workspace)
    if inventory["gaps"]:
        raise ValueError("normal source inventory is incomplete")
    observed = {row["path"]: row["sha256"] for row in inventory["files"]}
    if observed != product:
        raise ValueError(
            "normal inventory differs from registered source/configuration"
        )
    files = [
        workspace / row["path"]
        for row in inventory["files"]
        if row["language"] == "python"
    ]
    return inventory, files


def _startup_inventory(scanner, workspace, expected_files, audit, normal):
    if normal:
        from factoryline import deep_audit_io

        if not Path(deep_audit_io.__file__).resolve().is_relative_to(scanner):
            raise ValueError("frozen scanner inventory import identity mismatch")
        return _normal_inventory(workspace, expected_files)
    files = audit._security_source_files(workspace)
    if {p.relative_to(workspace).as_posix() for p in files} != set(expected_files):
        raise ValueError("source inventory differs from registered capture")
    return None, files


def startup(scanner, workspace, profile, expected_files):
    """Read source/config through the frozen API; never execute target modules."""
    normal = _normal_profile(profile)
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
    inventory, files = _startup_inventory(
        scanner, workspace, expected_files, audit, normal
    )
    if len(files) > audit._validate_source_file_limit(None):
        raise ValueError("source inventory exceeds scanner capacity")
    for path in files:
        relative = path.relative_to(workspace).as_posix()
        try:
            ast.parse(
                audit._security_source_bytes(workspace, relative), filename=relative
            )
        except (SyntaxError, ValueError, RecursionError) as error:
            raise ValueError(
                "unsupported captured Python syntax: " + relative
            ) from error
    _, collection = audit._pytest_collection_config(
        workspace, files, allow_unknown=normal or profile["security_only"] is True
    )
    if normal:
        return {
            "state": "PASS",
            "endpoint": profile["endpoint"],
            "files": len(inventory["files"]),
            "candidate_sha256": inventory["candidate_sha256"],
            "languages": inventory["languages"],
            "collection": collection,
            "native_execution": "NOT_RUN",
            "measurement_complete": False,
        }
    return {"state": "PASS", "files": len(files), "collection": collection}


def scanner_bundles(root, protocol, bindings):
    scanners = {}
    specification = protocol["scanner"]
    arms = specification.get("arms", ["baseline", "candidate"])
    if (
        not isinstance(arms, list)
        or not arms
        or any(arm not in ("baseline", "candidate") for arm in arms)
        or len(set(arms)) != len(arms)
    ):
        raise ValueError("invalid scanner arms")
    normal = _normal_profile(specification.get("profile", {}))
    for arm in arms:
        bundle = bound_path(root, protocol["scanner"][arm])
        manifest = bundle / "manifest.json"
        if normal:
            from factoryline.deep_audit_io import local_file

            manifest = local_file(
                root, (Path(specification[arm]) / "manifest.json").as_posix()
            )
        if digest(manifest) != protocol["scanner"][arm + "_manifest_sha256"]:
            raise ValueError("scanner manifest seal changed")
        bindings[str(manifest)] = digest(manifest)
        for name, expected in json.loads(manifest.read_text()).items():
            path = bound_path(bundle / "scanner", name)
            if normal:
                path = local_file(
                    root, (Path(specification[arm]) / "scanner" / name).as_posix()
                )
            if digest(path) != expected:
                raise ValueError("frozen scanner source changed")
            bindings[str(path)] = expected
        scanners[arm] = bundle / "scanner"
    return scanners


def _startup_expected_files(sources, normal):
    if normal:
        return [{"path": item["path"], "sha256": item["sha256"]} for item in sources]
    return [item["path"] for item in sources if item["kind"] == "python"]


def _bind_capture_inputs(root, source, row, normal, bindings):
    if normal:
        normal_registered_inputs(source, row["sources"])
    for item in row["sources"]:
        path = _input_file(
            root, (Path(row["source_root"]) / item["path"]).as_posix(), normal
        )
        if normal:
            from factoryline.deep_audit_io import _source_bytes

            raw, _ = _source_bytes(source, item["path"])
            current = hashlib.sha256(raw).hexdigest()
        else:
            current = digest(path)
        if current != item["sha256"]:
            raise ValueError("captured source/configuration changed")
        bindings[str(path)] = item["sha256"]
    return _startup_expected_files(row["sources"], normal)


def inputs(study):
    from factoryline.deep_audit_io import local_file

    study = Path(study).resolve()
    root = study.parents[1]
    registration = local_file(study, "registration.json")
    protocol = json.loads(registration.read_text(encoding="utf-8-sig"))
    normal = _normal_profile(protocol["scanner"].get("profile", {}))
    registration_seal = _input_file(study, "registration.sha256", normal)
    if digest(registration) != registration_seal.read_text().strip():
        raise ValueError("registration seal mismatch")
    capture = _input_file(study, "source-capture.json", normal)
    rows = json.loads(capture.read_text(encoding="utf-8-sig"))["repositories"]
    bindings = {
        str(registration): digest(registration),
        str(capture): digest(capture),
        str(Path(__file__).resolve()): digest(__file__),
        str(registration_seal): digest(registration_seal),
    }
    controller = _input_file(study, "study.py", normal)
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
        expected = _bind_capture_inputs(root, source, row, normal, bindings)
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
    if not all((bool(identities), len(set(identities)) == len(identities))):
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
    if (receipt.get("schema"), receipt.get("state")) != (SCHEMA, "PASS"):
        raise ValueError("cohort startup preflight has not passed")
    core = {k: v for k, v in receipt.items() if k != "receipt_sha256"}
    if receipt.get("receipt_sha256") != canonical(core):
        raise ValueError("preflight receipt seal mismatch")
    jobs, bindings, controller = inputs(receipt["study"])
    identities = [[row["repository"], row["arm"]] for row in jobs]
    observed = [[row["repository"], row["arm"]] for row in receipt["checks"]]
    if not all((receipt["expected"] == identities, observed == identities)):
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
