"""Run the registered native precision profile without writing to its source tree."""

import argparse
import json
import sys


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
    args = parser.parse_args(argv)
    try:
        code, report = scan_capture(args.root)
    except (OSError, ValueError, ReviewAuditError) as error:
        print(
            json.dumps(
                {"state": "INVALID", "message": _security_receipt_error_message(error)}
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
