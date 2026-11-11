"""Run the registered native precision profile without writing to its source tree."""

import argparse
import json
import sys
from pathlib import Path


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
    args = parser.parse_args(argv)
    try:
        destination = Path(args.out)
        if destination.resolve().is_relative_to(Path(args.root).resolve()):
            raise ValueError("The report must be outside the capture root.")
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("The report destination already exists.")
        code, report = scan_capture(args.root)
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except (OSError, ValueError, ReviewAuditError) as error:
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
