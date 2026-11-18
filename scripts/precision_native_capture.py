"""Run the registered native precision profile without writing to its source tree."""

import argparse
import hashlib
import json
import sys
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


def main(argv=None):
    from factoryline.cli_audit import _security_receipt_error_message
    from factoryline.review_audits import ReviewAuditError

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
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
        code, report = scan_capture(args.root)
        if args.observation_manifest is not None:
            inventory = json.loads(args.observation_manifest.read_bytes())["sources"]
            report = project_paired_observation(report, inventory)
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except (KeyError, TypeError, OSError, ValueError, ReviewAuditError) as error:
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


if __name__ == "__main__":
    raise SystemExit(main())
