"""Run the registered native precision profile without writing to its source tree."""

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


_FINDING_FIELDS = ("code", "path", "line", "column", "end_line", "end_column")


class NativeObservationError(ValueError):
    def __init__(self, checks):
        self.checks = checks
        super().__init__("Native observation failed: " + ", ".join(checks))


def project_paired_observation(report, inventory):
    """Keep complete native diagnostics even when policy admission is unavailable."""
    sources = {row["path"]: row["sha256"] for row in inventory}
    checks = _report_checks(report, inventory, sources)
    failures = [name for name, passed in checks.items() if not passed]
    if failures:
        raise NativeObservationError(failures)
    admission_available = report["defect_policy_decision"]["state"] != "BLOCKED"
    findings = _project_findings(report, sources, admission_available)
    return dict(
        schema="factory.precision.native-observation.v1",
        admission_available=admission_available,
        raw=findings,
    )


def _source_inventory_matches(report, inventory, sources):
    python = {
        row["path"]: row["sha256"] for row in inventory if row["kind"] == "python"
    }
    observed = {row["path"]: row["sha256"] for row in report["sources"]}
    return (
        len(sources) == len(inventory)
        and len(observed) == len(report["sources"])
        and observed == python
        and all(
            sources.get(row["path"]) == row["sha256"]
            for row in report["oracle_context"]["configuration_sources"]
        )
    )


def _report_checks(report, inventory, sources):
    coverage = report["audit_coverage"]
    validation = report["finding_tier_report"]["validation"]
    decision = report["defect_policy_decision"]["state"]
    return {
        "source_identity": _source_inventory_matches(report, inventory, sources),
        "coverage": (
            coverage["complete"] is True
            and coverage["inventory_complete"] is True
            and validation["coverage_state"] is True
        ),
        "finding_conservation": (
            validation["partition_state"] == "VALIDATED"
            and report["finding_conservation"]["state"] == "PASS"
        ),
        "defect_policy": (
            report["selected_defect_policy"] == "source-role-v3"
            and decision
            in {"BLOCKED", "DEFECTS_PRESENT", "NO_SUPPORTED_DEFECTS_REVIEW_REQUIRED"}
        ),
    }


def _security_rows(rows, field):
    return (row for row in rows if row[field]["code"].startswith("SECURITY_"))


def _security_actions(report):
    actions = {}
    for action in _security_rows(report["agent_actions"], "finding_context"):
        identity = tuple(action["finding_context"][key] for key in _FINDING_FIELDS)
        if (
            identity in actions
            or action["candidate_sha256"] != report["candidate_sha256"]
        ):
            raise NativeObservationError(["finding_conservation"])
        actions[identity] = action
    return actions


def _project_findings(report, sources, admission_available):
    actions = _security_actions(report)
    findings = {}
    entries = _security_rows(report["finding_tier_report"]["ledger"], "raw_finding")
    for entry in entries:
        identity = tuple(entry["raw_finding"][key] for key in _FINDING_FIELDS)
        findings[identity] = _project_finding(
            entry,
            identity,
            sources,
            actions.pop(identity, None),
            admission_available,
            duplicate=identity in findings,
        )
    if actions:
        raise NativeObservationError(["finding_conservation"])
    return list(findings.values())


def _project_finding(
    entry, identity, sources, action, admission_available, *, duplicate
):
    raw = entry["raw_finding"]
    source = entry["source_identity"]
    digest = hashlib.sha256(
        json.dumps(
            raw,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()
    admitted = entry["tier"] == "SUPPORTED_DEFECT" if admission_available else None
    action_matches = (
        (action["finding_context"] == raw, action["finding_sha256"] == digest)
        if action is not None
        else ()
    )
    if (
        source["path"] != raw["path"]
        or sources.get(raw["path"]) != source["source_sha256"]
    ):
        raise NativeObservationError(["source_identity"])
    if (
        duplicate
        or (admitted is True) != (action is not None)
        or not all(action_matches)
    ):
        raise NativeObservationError(["finding_conservation"])
    return dict(
        identity=list(identity),
        source_sha256=source["source_sha256"],
        raw_sha256=digest,
        tier=entry["tier"],
        admitted=admitted,
    )


def scan_capture(root):
    from factoryline.cli import _build_parser
    from factoryline.cli_audit import (
        bounded_security_exit_code,
        prepare_bounded_security_report,
    )

    args = _build_parser().parse_args(
        [
            "audit",
            "security",
            "--root",
            str(root),
            "--security-only",
            "--defect-policy",
            "source-role-v3",
            "--json",
        ]
    )
    report = prepare_bounded_security_report(args)
    return bounded_security_exit_code(args, report), report


def _normal_digest(value):
    from factoryline.deep_audit_io import digest

    return digest(value)


def _normal_sources(root, inventory):
    from factoryline.deep_audit_io import local_file
    from factoryline.runtime_audit_process import bounded_file_sha256

    sources, total = {}, 0
    if not isinstance(inventory, list) or len(inventory) > 200:
        raise NativeObservationError(["source_identity"])
    for row in inventory:
        path, digest = row["path"], row["sha256"]
        bound = local_file(root, path)
        total += bound.stat().st_size
        if (
            total > 16 * 1024 * 1024
            or path in sources
            or bounded_file_sha256(bound, 16 * 1024 * 1024) != digest
        ):
            raise NativeObservationError(["source_identity"])
        sources[path] = digest
    return sources


def _normal_native_bindings_present(lane):
    return all(
        isinstance(lane.get(field), str)
        and len(lane[field]) == 64
        and all(c in "0123456789abcdef" for c in lane[field])
        for field in (
            "bundle_sha256",
            "report_sha256",
            "coverage_sha256",
            "challenge_sha256",
        )
    )


def _normal_native_lanes(report):
    workers = [
        row["result"]
        for row in report["deep_audit"]["lanes"]
        if row.get("measurement_id") == "native_worker_execution"
    ]
    if (
        not workers
        and report["static_security"]["finding_conservation"].get("native_raw_rows")
        == 0
    ):
        return []
    if len(workers) != 1:
        raise NativeObservationError(["native_ledger"])
    lanes = workers[0].get("lanes", [])
    selected = [row for row in lanes if row.get("findings")]
    for lane in selected:
        if lane.get("state") != "OBSERVED" or lane.get("gaps") != []:
            raise NativeObservationError(["native_ledger"])
        if not _normal_native_bindings_present(lane):
            raise NativeObservationError(["native_bindings"])
    return selected


def _normal_worker_measurement_complete(worker):
    coverage = worker["action_coverage"]
    count = len(worker["lanes"])
    return (
        worker["analysis_complete"] is True
        and worker["state"] in {"COMPLETE", "PASS", "OBSERVED"}
        and worker["gaps"] == []
        and isinstance(coverage, dict)
        and coverage.get("state") == "VERIFIED"
        and all(
            type(coverage.get(key)) is int and coverage[key] == count
            for key in ("expected_count", "started_count", "terminal_count")
        )
        and all(
            coverage.get(key) == []
            for key in (
                "missing_starts",
                "missing_terminals",
                "duplicates",
                "unexpected",
                "mismatches",
            )
        )
        and all(
            lane["state"] == "OBSERVED"
            and lane["gaps"] == []
            and lane["evidence_bindings_present"]
            for lane in worker["lanes"]
        )
    )


def _normal_measurement(report):
    workers = []
    for row in report["deep_audit"]["lanes"]:
        if row.get("measurement_id") != "native_worker_execution":
            continue
        result = row.get("result") or {}
        workers.append(
            {
                "state": result.get("state", row.get("state")),
                "analysis_complete": result.get("analysis_complete"),
                "gaps": result.get("gaps"),
                "action_coverage": result.get("action_coverage"),
                "lanes": [
                    {
                        **{
                            key: lane.get(key)
                            for key in (
                                "lane_id",
                                "engine",
                                "family",
                                "state",
                                "gaps",
                                "bundle_sha256",
                                "report_sha256",
                                "coverage_sha256",
                                "challenge_sha256",
                            )
                        },
                        "raw_count": len(lane.get("findings", [])),
                        "evidence_bindings_present": _normal_native_bindings_present(
                            lane
                        ),
                    }
                    for lane in result.get("lanes", [])
                ],
            }
        )
    static = report["static_security"]
    python = static["python_ast_security"]
    coverage = {
        "static_security": static.get("audit_coverage"),
        "python_ast_security": python.get("audit_coverage"),
        "deep_audit": report["deep_audit"].get("coverage"),
    }
    complete = (
        (coverage["static_security"] or {}).get("complete") is True
        and (
            python.get("state") == "NO_SOURCES"
            or (coverage["python_ast_security"] or {}).get("complete") is True
        )
        and bool(workers)
        and all(_normal_worker_measurement_complete(worker) for worker in workers)
    )
    return {
        "measurement_complete": complete,
        "measurement_basis": "producer_metadata_only",
        "score_eligible": False,
        "native_diagnostics": {"workers": workers},
        "producer_coverage": coverage,
    }


def _normal_row(raw, sources, *, identity, tier, lane=None):
    source_hash = raw.get("source_sha256")
    if lane is None:
        source_hash = sources.get(raw["path"])
    if not source_hash or sources.get(raw["path"]) != source_hash:
        raise NativeObservationError(["source_identity"])
    result = {
        "identity": identity,
        "source_sha256": source_hash,
        "raw_sha256": _normal_digest(raw),
        "raw_finding": raw,
        "tier": tier,
        "admitted": None,
    }
    if lane is not None:
        result["native_bindings"] = {
            key: lane[key]
            for key in (
                "lane_id",
                "engine",
                "bundle_sha256",
                "report_sha256",
                "coverage_sha256",
                "challenge_sha256",
            )
        }
    return result


def _normal_rows(report, sources):
    static = report["static_security"]
    rows, originals = [], []
    for entry in _normal_python_entries(static, sources):
        raw = entry["raw_finding"]
        if (
            entry["source_identity"]["source_sha256"] != sources.get(raw["path"])
            or entry["source_identity"]["path"] != raw["path"]
        ):
            raise NativeObservationError(["source_identity"])
        rows.append(
            _normal_row(
                raw,
                sources,
                identity=["python", *[raw[key] for key in _FINDING_FIELDS]],
                tier=entry["tier"],
            )
        )
        originals.append(raw)
    for lane in _normal_native_lanes(report):
        for raw in lane["findings"]:
            if (
                raw.get("lane_id") != lane["lane_id"]
                or not raw.get("finding_id")
                or not raw.get("rule_id")
            ):
                raise NativeObservationError(["native_identity"])
            rows.append(
                _normal_row(
                    raw,
                    sources,
                    identity=[
                        "native",
                        lane["engine"],
                        lane["lane_id"],
                        raw["finding_id"],
                    ],
                    tier="UNASSESSED",
                    lane=lane,
                )
            )
            originals.append(raw)
    if sorted(map(_normal_digest, originals)) != sorted(
        map(_normal_digest, static["findings"])
    ):
        raise NativeObservationError(["finding_conservation"])
    identities = [json.dumps(row["identity"], sort_keys=True) for row in rows]
    if len(set(identities)) != len(identities):
        raise NativeObservationError(["finding_conservation"])
    return rows


def _normal_python_entries(static, sources):
    python = static["python_ast_security"]
    if python.get("state") == "NO_SOURCES":
        if (
            python.get("findings") != []
            or any(path.endswith(".py") for path in sources)
            or static.get("python_finding_conservation") != {}
        ):
            raise NativeObservationError(["python_producer"])
        return []
    _normal_python_seals(python)
    entries = python["finding_tier_report"]["ledger"]
    if (
        static.get("finding_tier_report") != python["finding_tier_report"]
        or static["python_finding_conservation"] != python["finding_conservation"]
        or sorted(_normal_digest(row["raw_finding"]) for row in entries)
        != sorted(map(_normal_digest, python["findings"]))
    ):
        raise NativeObservationError(["python_producer"])
    return entries


def _normal_python_seals(python):
    body = {key: value for key, value in python.items() if key != "audit_sha256"}
    source_body = {
        key: python[key] for key in ("sources", "oracle_context", "database_context")
    }
    if python.get("audit_sha256") != _normal_digest(body) or python.get(
        "source_manifest_sha256"
    ) != _normal_digest(source_body):
        raise NativeObservationError(["python_producer_seal"])


def project_normal_observation(raw_report, inventory, *, root, report_sha256):
    """Project pinned normal CLI output; never authenticate execution or policy admission."""
    _normal_report_hash(report_sha256)
    if (
        not isinstance(raw_report, bytes)
        or len(raw_report) > 16 * 1024 * 1024
        or hashlib.sha256(raw_report).hexdigest() != report_sha256
    ):
        raise NativeObservationError(["report_binding"])
    from factoryline.deep_audit_io import strict_json

    report = strict_json(raw_report)
    sources = _normal_sources(Path(root).resolve(strict=True), inventory)
    static = report["static_security"]
    _normal_report_seals(static)
    observed = {row["path"]: row["sha256"] for row in static["sources"]}
    if len(observed) != len(static["sources"]) or any(
        sources.get(path) != value for path, value in observed.items()
    ):
        raise NativeObservationError(["source_identity"])
    rows = _normal_rows(report, sources)
    _normal_conservation(static, rows)
    if any(row["raw_finding"]["path"] not in observed for row in rows):
        raise NativeObservationError(["source_identity"])
    if _normal_sources(Path(root).resolve(strict=True), inventory) != sources:
        raise NativeObservationError(["source_identity"])
    return {
        "schema": "factory.precision.normal-observation.v1",
        **_normal_measurement(report),
        "authority": "none",
        "claim_boundary": "Pinned report projection only; execution, collector invocation and reference labels require separate verification.",
        "execution_verified": False,
        "admission_available": False,
        "input_state": report.get("state"),
        "candidate_sha256": static.get("candidate_sha256"),
        "normal_report_sha256": report_sha256,
        "source_manifest_sha256": _normal_digest(inventory),
        "sources": sources,
        "raw_count": len(rows),
        "admitted_count": None,
        "raw": rows,
    }


def _normal_report_seals(static):
    from factoryline.adoption import _digest

    body = {key: value for key, value in static.items() if key != "audit_sha256"}
    if static.get("audit_sha256") != _digest(body) or static.get(
        "source_manifest_sha256"
    ) != _digest(static["sources"]):
        raise NativeObservationError(["report_conservation_binding"])
    counts = Counter(
        row.get("code") or row.get("rule_id") or row.get("id") or "UNCLASSIFIED"
        for row in static["findings"]
    )
    declared = static.get("finding_counts")
    if (
        not isinstance(declared, dict)
        or any(type(value) is not int for value in declared.values())
        or declared != dict(counts)
        or type(static.get("source_binding_count")) is not int
        or static["source_binding_count"] != len(static["sources"])
    ):
        raise NativeObservationError(["finding_conservation"])


def _normal_conservation(static, rows):
    native = sum(
        row["tier"] == "UNASSESSED" and "native_bindings" in row for row in rows
    )
    expected = {
        "state": "UNASSESSED",
        "scope": "mixed_diagnostic_identity_multiplicity",
        "expected_raw_rows": len(rows),
        "physical_raw_rows": len(rows),
        "python_rows": len(rows) - native,
        "native_raw_rows": native,
        "native_policy_state": "UNASSESSED",
    }
    conservation = static["finding_conservation"]
    if (
        static.get("schema") != "factory.mixed-security-audit.v1"
        or static.get("policy_scope") != "python_ast_security"
        or any(
            type(conservation.get(key)) is not type(value)
            or conservation.get(key) != value
            for key, value in expected.items()
        )
        or static["python_finding_conservation"].get("state", "NO_SOURCES")
        not in {"PASS", "NO_SOURCES"}
    ):
        raise NativeObservationError(["finding_conservation"])


def _normal_report_hash(value):
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise NativeObservationError(["report_binding"])
    return value


def _load_normal_observation(args):
    from factoryline.runtime_audit_process import bounded_file_sha256
    from factoryline.deep_audit_io import strict_json

    if args.observation_manifest is None:
        raise NativeObservationError(["registered_inventory_required"])
    expected = _normal_report_hash(args.normal_report_sha256)
    digest, raw = bounded_file_sha256(
        args.normal_report, 16 * 1024 * 1024, include_bytes=True
    )
    if digest != expected:
        raise NativeObservationError(["report_binding"])
    _, manifest = bounded_file_sha256(
        args.observation_manifest, 16 * 1024 * 1024, include_bytes=True
    )
    inventory = strict_json(manifest)["sources"]
    return project_normal_observation(
        raw, inventory, root=args.root, report_sha256=digest
    )


def main(argv=None):
    from factoryline.cli_audit import _security_receipt_error_message
    from factoryline.review_audits import ReviewAuditError

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument(
        "--normal-report",
        type=Path,
        help="Project an existing normal CLI report; never collect or execute it",
    )
    parser.add_argument(
        "--normal-report-sha256",
        help="Required immutable report digest with --normal-report",
    )
    parser.add_argument(
        "--out", required=True, help="New report file outside the capture"
    )
    parser.add_argument(
        "--observation-manifest",
        type=Path,
        help="Project a compact observation against a registered capture inventory",
    )
    args = parser.parse_args(argv)
    try:
        destination = Path(args.out)
        if destination.resolve().is_relative_to(Path(args.root).resolve()):
            raise ValueError("The report must be outside the capture root.")
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("The report destination already exists.")
        code, report = _capture_observation(args)
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except (
        KeyError,
        TypeError,
        AttributeError,
        IndexError,
        OSError,
        ValueError,
        ReviewAuditError,
    ) as error:
        diagnostic = {
            "state": "INVALID",
            "message": _security_receipt_error_message(error),
        }
        if isinstance(error, NativeObservationError):
            diagnostic["failed_checks"] = error.checks
        print(
            json.dumps(diagnostic),
            file=sys.stderr,
        )
        return 2
    return code


def _capture_observation(args):
    if args.normal_report is not None:
        return 0, _load_normal_observation(args)
    if args.normal_report_sha256 is not None:
        raise NativeObservationError(["normal_report_required"])
    code, report = scan_capture(args.root)
    if args.observation_manifest is not None:
        inventory = json.loads(args.observation_manifest.read_bytes())["sources"]
        report = project_paired_observation(report, inventory)
    return code, report


if __name__ == "__main__":
    raise SystemExit(main())
