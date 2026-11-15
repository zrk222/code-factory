"""Run the registered native precision profile without writing to its source tree."""

import argparse
import hashlib
import json
import sys
from pathlib import Path


def project_paired_observation(report, inventory):
    """Keep complete native diagnostics even when policy admission is unavailable."""
    sources = {row["path"]: row["sha256"] for row in inventory}
    python = {
        row["path"]: row["sha256"] for row in inventory if row["kind"] == "python"
    }
    observed = {row["path"]: row["sha256"] for row in report["sources"]}
    coverage = report["audit_coverage"]
    tiers = report["finding_tier_report"]
    decision = report["defect_policy_decision"]["state"]
    if not all(
        (
            len(sources) == len(inventory),
            len(observed) == len(report["sources"]),
            observed == python,
            coverage["complete"] is True,
            coverage["inventory_complete"] is True,
            tiers["validation"]["coverage_state"] is True,
            tiers["validation"]["partition_state"] == "VALIDATED",
            report["finding_conservation"]["state"] == "PASS",
            report["selected_defect_policy"] == "source-role-v3",
            decision
            in {"BLOCKED", "DEFECTS_PRESENT", "NO_SUPPORTED_DEFECTS_REVIEW_REQUIRED"},
            all(
                sources.get(row["path"]) == row["sha256"]
                for row in report["oracle_context"]["configuration_sources"]
            ),
        )
    ):
        raise ValueError("Native observation is incomplete or source binding changed.")
    fields = ("code", "path", "line", "column", "end_line", "end_column")
    actions, findings = {}, {}
    security_actions = (
        row
        for row in report["agent_actions"]
        if row["finding_context"]["code"].startswith("SECURITY_")
    )
    for action in security_actions:
        raw = action["finding_context"]
        identity = tuple(raw[key] for key in fields)
        if (
            identity in actions
            or action["candidate_sha256"] != report["candidate_sha256"]
        ):
            raise ValueError("Native action binding changed.")
        actions[identity] = action
    security_entries = (
        row
        for row in tiers["ledger"]
        if row["raw_finding"]["code"].startswith("SECURITY_")
    )
    for entry in security_entries:
        raw = entry["raw_finding"]
        identity = tuple(raw[key] for key in fields)
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
        action = actions.pop(identity, None)
        admitted = (
            entry["tier"] == "SUPPORTED_DEFECT" if decision != "BLOCKED" else None
        )
        action_matches = (
            (
                action["finding_context"] == raw,
                action["finding_sha256"] == digest,
            )
            if action is not None
            else ()
        )
        if not all(
            (
                identity not in findings,
                source["path"] == raw["path"],
                sources.get(raw["path"]) == source["source_sha256"],
                (admitted is True) == (action is not None),
                all(action_matches),
            )
        ):
            raise ValueError(
                "Native finding identity, source, or action binding changed."
            )
        findings[identity] = dict(
            identity=list(identity),
            source_sha256=source["source_sha256"],
            raw_sha256=digest,
            tier=entry["tier"],
            admitted=admitted,
        )
    if actions:
        raise ValueError("Native observation contains unmapped actions.")
    return dict(
        schema="factory.precision.native-observation.v1",
        admission_available=decision != "BLOCKED",
        raw=list(findings.values()),
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
        print(
            json.dumps(
                {"state": "INVALID", "message": _security_receipt_error_message(error)}
            ),
            file=sys.stderr,
        )
        return 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
