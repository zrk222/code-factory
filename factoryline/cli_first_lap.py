"""CLI boundary for the human-observed First Lap activation gate."""

from __future__ import annotations

import json
import hashlib
import re
import sys
from pathlib import Path
from typing import Any


def add_scan_parser(sub: Any) -> None:
    """Register the same scan options for quick and full discovery."""
    scan = sub.add_parser(
        "scan",
        help="check your code and show findings, missing checks, and next steps",
        description="Default scan runs applicable local checks and authorized configured workers. Use --static-only for Python source checks without workers.",
        epilog="Exit 0: no blocking findings/checks (advisories may remain). Exit 2: blocked or invalid analysis. INCOMPLETE means evidence gaps remain; it is not release approval. Base static analysis covers Python; other languages require workers.",
    )
    scan.add_argument("--root", default=".")
    scan.add_argument(
        "--max-files",
        type=int,
        help="Python source budget, 1..2000 (default: 2000); over-budget inventories are blocked without truncation",
    )
    scan_scope = scan.add_mutually_exclusive_group()
    scan_scope.add_argument(
        "--deep",
        action="store_true",
        default=True,
        help="use the default full local scan (retained for compatibility)",
    )
    scan_scope.add_argument(
        "--static-only",
        action="store_false",
        dest="deep",
        help="check Python source only, without configured workers",
    )
    scan.add_argument(
        "--worker-config",
        help="workspace-relative signed worker configuration; otherwise discover .factory/native-worker-config.json",
    )
    formats = scan.add_mutually_exclusive_group()
    for flag in ("json", "sarif", "output-contract", "pre-commit-config"):
        formats.add_argument("--" + flag, action="store_true")
    scan.add_argument(
        "--require-complete",
        action="store_true",
        help="CI policy: exit 2 unless state and verdict are both PASS; retain advisory default",
    )
    for flag, help_text in (
        ("oracle-evidence", "workspace-relative DSSE per-test mutation attestation"),
        ("oracle-trust-root", "workspace-relative oracle-verifier public trust root"),
        ("oracle-trust-sha256", "operator-pinned trust root SHA-256"),
        ("oracle-environment-sha256", "expected runner/environment contract SHA-256"),
    ):
        scan.add_argument("--" + flag, help=help_text)


def add_parser(sub: Any) -> None:
    """Register scan and the First Lap activation and observation commands."""
    first_proof = sub.add_parser(
        "first-proof",
        help="run a local sandbox demonstration and bounded workspace inventory",
    )
    first_proof.add_argument("--root", default=".")
    first_proof.add_argument("--out-dir", help="workspace-contained output directory")
    first_proof.add_argument("--json", action="store_true")
    add_scan_parser(sub)
    first_lap = sub.add_parser(
        "first-lap", help="prepare and verify the human-observed first activation lap"
    )
    first_lap_sub = first_lap.add_subparsers(required=True, dest="first_lap_cmd")
    first_lap_init = first_lap_sub.add_parser(
        "init",
        help="write MISSION.md, END-TO-END.md, verifier-only HOLDOUT.md, and an immutable receipt",
    )
    first_lap_init.add_argument("--root", default=".")
    first_lap_init.add_argument(
        "--mission",
        default="Deliver the requested outcome without violating the forbidden outcomes.",
    )
    first_lap_init.add_argument("--journey", action="append", dest="journeys")
    first_lap_init.add_argument("--holdout", action="append", dest="holdouts")
    first_lap_init.add_argument(
        "--force",
        action="store_true",
        help="replace only the generated files and receipt",
    )
    first_lap_init.add_argument("--json", action="store_true")
    first_lap_status = first_lap_sub.add_parser(
        "status",
        help="read and integrity-check the initialized First Lap files without executing them",
    )
    first_lap_status.add_argument("--root", default=".")
    first_lap_status.add_argument("--json", action="store_true")
    first_lap_calibrate = first_lap_sub.add_parser(
        "calibrate",
        help="verify approved, defective, and wrong-candidate calibration cases",
    )
    first_lap_calibrate.add_argument(
        "input",
        help="JSON object containing approved_candidate, defective_candidate, and wrong_candidate statuses",
    )
    first_lap_calibrate.add_argument("--root", default=".")
    first_lap_calibrate.add_argument(
        "--strict",
        action="store_true",
        help="require candidate and contract identity bindings",
    )
    first_lap_calibrate.add_argument("--json", action="store_true")
    first_lap_incident = first_lap_sub.add_parser(
        "incident", help="append a complete incident-to-invariant chain"
    )
    first_lap_incident.add_argument("input", help="incident JSON object")
    first_lap_incident.add_argument("--root", default=".")
    first_lap_incident.add_argument(
        "--promote",
        action="store_true",
        help="also compile the incident into a permanent regression gate",
    )
    first_lap_incident.add_argument("--json", action="store_true")
    first_lap_promote = first_lap_sub.add_parser(
        "promote",
        help="compile an incident JSON object into a permanent regression gate",
    )
    first_lap_promote.add_argument("input", help="incident JSON object")
    first_lap_promote.add_argument("--root", default=".")
    first_lap_promote.add_argument("--json", action="store_true")
    first_lap_holdout = first_lap_sub.add_parser(
        "holdout", help="verify verifier-only holdout binding and contamination state"
    )
    first_lap_holdout.add_argument("input", help="holdout boundary JSON object")
    first_lap_holdout.add_argument("--root", default=".")
    first_lap_holdout.add_argument("--json", action="store_true")
    first_lap_holdout.add_argument(
        "--strict", action="store_true", help="require an externally isolated holdout"
    )
    first_lap_observe = first_lap_sub.add_parser(
        "observe", help="verify the exact human-observed first-lap phase sequence"
    )
    first_lap_observe.add_argument(
        "input", help="JSON array of phase/evidence_sha256 events"
    )
    first_lap_observe.add_argument(
        "--strict",
        action="store_true",
        help="require named human observer and run metadata",
    )
    first_lap_observe.add_argument("--json", action="store_true")
    first_lap_failure = first_lap_sub.add_parser(
        "failure", help="classify a failure and derive its retry policy"
    )
    first_lap_failure.add_argument(
        "kind",
        choices=[
            "definitive_product_failure",
            "transient_provider_failure",
            "unverifiable_candidate_identity",
            "stale_evidence",
            "environment_setup_failure",
        ],
    )
    first_lap_failure.add_argument("--provider")
    first_lap_failure.add_argument("--retry-after", type=int)
    first_lap_failure.add_argument(
        "--strict",
        action="store_true",
        help="require provider evidence for retryable failures",
    )
    first_lap_failure.add_argument("--json", action="store_true")
    first_lap_verify = first_lap_sub.add_parser(
        "verify",
        help="compose calibration, holdout, and observed-lap receipts into one activation gate",
    )
    first_lap_verify.add_argument("--calibration", required=True)
    first_lap_verify.add_argument("--holdout", required=True)
    first_lap_verify.add_argument("--observed", required=True)
    first_lap_verify.add_argument("--root", default=".")
    first_lap_verify.add_argument(
        "--strict",
        action="store_true",
        help="require all identity, isolation, observation, and incident gates",
    )
    first_lap_verify.add_argument(
        "--persist", action="store_true", help="write immutable activation receipt"
    )
    first_lap_verify.add_argument("--json", action="store_true")


def run(args: Any) -> int:
    """Execute a First Lap command after parser selection."""
    if args.cmd == "first-proof":
        return _run_first_proof(args)
    if args.cmd == "scan":
        return _run_scan(args)
    from . import first_lap

    workspace = (
        Path(args.root).resolve() if hasattr(args, "root") else Path(".").resolve()
    )
    try:
        result, code = _execute_first_lap_command(args, workspace, first_lap)
    except (
        first_lap.FirstLapError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        result = _first_lap_error(exc)
        code = 2
    _render_first_lap_result(args, result, code)
    return code


def _run_first_proof(args: Any) -> int:
    from .adoption import AdoptionError, run_first_proof
    from .e2e_proof import E2EProofError

    try:
        result = run_first_proof(
            Path(args.root).resolve(),
            out_dir=Path(args.out_dir) if args.out_dir else None,
        )
    except (AdoptionError, E2EProofError, OSError) as exc:
        error = {
            "schema": "factory.first-proof.error.v1",
            "code": getattr(exc, "code", "E_FIRST_PROOF_FAILED"),
            "message": str(exc),
        }
        print(
            json.dumps(error, indent=2, sort_keys=True)
            if args.json
            else f"first proof failed: {error['code']}: {exc}",
            file=sys.stderr,
        )
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("factory first-proof")
        print("=" * 44)
        print("result   : HOLLOW_TEST_DETECTED")
        print(
            "meaning  : the sandbox negative check also passed, so the test could not say no"
        )
        print(f"receipt  : {result['activation_path']}")
        print(f"share    : {result['proof_card']['paths']['svg']}")
        print(
            "boundary : sandbox demo plus bounded inventory; no project code was executed or uploaded"
        )
    return 0


def _run_scan(args: Any) -> int:
    if getattr(args, "output_contract", False):
        try:
            contract = scan_output_contract()
        except (OSError, ValueError, UnicodeError):
            return _scan_interface_error()
        print(json.dumps(contract, indent=2, sort_keys=True))
        return 0
    if getattr(args, "pre_commit_config", False):
        print(_precommit_configuration(), end="")
        return 0
    from .adoption import run_repo_scan

    try:
        result = run_repo_scan(
            Path(args.root).resolve(),
            max_files=args.max_files,
            deep=args.deep,
            worker_config=args.worker_config,
            oracle_options={
                name: getattr(args, name, None)
                for name in (
                    "oracle_evidence",
                    "oracle_trust_root",
                    "oracle_trust_sha256",
                    "oracle_environment_sha256",
                )
                if getattr(args, name, None) is not None
            },
        )
        code = 2 if result["state"] == "BLOCKED" else 0
        if getattr(args, "require_complete", False) and (
            result.get("state") != "PASS" or result.get("verdict") != "PASS"
        ):
            code = 2
    except (OSError, UnicodeError, ValueError) as exc:
        result = {
            "schema": "factory.repo-scan.error.v1",
            "state": "INVALID",
            "verdict": "INCOMPLETE",
            "message": str(exc),
        }
        code = 2
    if getattr(args, "sarif", False):
        try:
            document = _scan_sarif(result, code)
        except (OSError, ValueError, UnicodeError):
            return _scan_interface_error()
        print(json.dumps(document, indent=2, sort_keys=True))
    elif args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_repo_scan(result, code)
    return code


def _print_repo_scan(result: dict, code: int) -> None:
    print("factory scan\n" + "=" * 44)
    print(f"state    : {result['state']}")
    print(f"verdict  : {result['verdict']}")
    assessment = result.get("assessment", {})
    print(
        f"inventory: {assessment.get('files_discovered', 0)} files ({assessment.get('inventory_sha256', 'unavailable')[:12]})"
    )
    security = result.get("static_security", {})
    coverage = security.get("audit_coverage", {})
    print(
        f"security : {security.get('state', 'unavailable')}; Python audited {coverage.get('files_audited', 0)}/{coverage.get('files_discovered', 0)}, limit {coverage.get('limit', 'unavailable')}"
    )
    collection = security.get("oracle_context", {}).get("static_pytest_collection", {})
    if collection.get("collection_state") == "UNKNOWN":
        print(
            f"collection: UNKNOWN ({collection.get('path') or 'collection hooks'}; {collection.get('reason', 'unmodeled collection')}); source findings retained; test behavior has not been verified."
        )
    elif collection.get("collection_state") == "DISCOVERY_ONLY":
        print(
            f"collection: {len(collection['static_test_sources'])} test modules and "
            f"{len(collection['static_doctest_sources'])} Python doctest modules matched static discovery; "
            "imports and test behavior have not been verified."
        )
    print(
        "scope    : Python source checks; JS/shell and other languages require configured workers."
    )
    print(
        f"exit     : {code}; 0=no blocking findings/checks (advisories may remain), 2=blocked/invalid."
    )
    print(
        "evidence : INCOMPLETE means missing evidence or review; a clean static scan is not runtime coverage or release approval."
    )
    _print_scan_findings(result)
    for lane in (result.get("deep_audit") or {}).get("lanes", []):
        if lane.get("state") == "BLOCKED":
            label = {
                "python_ast_security": "Python security checks",
                "native_worker_execution": "Configured workers",
                "runtime_coverage": "Runtime coverage",
                "dependencies_and_supply_chain": "Dependencies and supply chain",
            }.get(lane["measurement_id"], lane["measurement_id"])
            print(
                f"blocking : {label}: {lane.get('next_action', 'Review this check.')}"
            )
    for action in result.get("next_actions", []):
        print(f"next     : {action}")
    error = (
        result.get("message")
        or result.get("static_security_error")
        or security.get("message")
    )
    if error:
        print(f"error    : {error}", file=sys.stderr)


def _scan_findings(result: dict) -> list:
    findings = list(result.get("static_security", {}).get("findings", []))
    deep = result.get("deep_audit") or {}
    findings.extend(deep.get("native_domains", {}).get("findings", []))
    for lane in deep.get("lanes", []):
        if lane.get("measurement_id") != "python_ast_security":
            findings.extend((lane.get("result") or {}).get("findings", []))
    # The scan and lane projections can contain the same native observation.
    seen_native = set()
    displayed = []
    for row in findings:
        identity = (row.get("lane_id"), row.get("finding_id"))
        if all(identity):
            if identity in seen_native:
                continue
            seen_native.add(identity)
        displayed.append(row)
    return displayed


def _print_scan_findings(result: dict) -> None:
    displayed = _scan_findings(result)
    print(f"findings : {len(displayed)}")
    for row in displayed:
        print(
            f"  {row.get('severity', 'INFO')} {row.get('code', row.get('rule_id', row.get('finding_id', 'FINDING')))} {row.get('path', '.')}:{row.get('line', 1)}:{row.get('column', 0)} - {row.get('message', row.get('summary', row.get('remediation', 'Review finding evidence.')))}"
        )


def _scan_interface_error() -> int:
    print(
        json.dumps(
            {
                "schema": "factory.scan-interface.error.v1",
                "state": "INVALID",
                "message": "Bundled scan output contract is unavailable or invalid.",
            }
        ),
        file=sys.stderr,
    )
    return 2


def scan_output_contract() -> dict:
    """Discover the bundled additive output boundary without scanning a workspace."""
    from importlib.resources import files

    raw = files("factoryline").joinpath("data/repo_scan.schema.json").read_bytes()
    schema = json.loads(raw)
    if (
        not isinstance(schema, dict)
        or schema.get("$id") != "urn:code-factory:repo-scan:v1"
        or "$schema" not in schema
    ):
        raise ValueError("Invalid bundled scan output contract")
    return {
        "schema": "factory.scan-interface-discovery.v1",
        "contract_sha256": hashlib.sha256(raw).hexdigest(),
        "output_schema": schema,
    }


def _precommit_configuration() -> str:
    return (
        "repos:\n  - repo: local\n    hooks:\n"
        "      - id: code-factory-scan\n        name: Code Factory static scan\n"
        "        entry: factory scan --static-only --sarif --root .\n"
        "        language: system\n        pass_filenames: false\n"
        "        require_serial: true\n        types_or: [python]\n"
        "        stages: [pre-commit]\n"
    )


def _sarif_rule(row: dict) -> str:
    value = row.get("code") or row.get("rule_id") or "FINDING"
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value):
        return value
    return "FINDING"


def _sarif_message(row: dict) -> str:
    value = row.get("message") or row.get("summary") or row.get("remediation")
    if not isinstance(value, str):
        return "Review finding evidence."
    # External diagnostic text is untrusted; do not export local absolute roots.
    value = re.sub(r"(?:\\\\|[A-Za-z]:[\\/]|(?<!\w)/)[^\s]+", "[local path]", value)
    return (
        "".join(c if c.isprintable() else " " for c in value)[:2048]
        or "Review finding evidence."
    )


def _sarif_location(row: dict) -> list:
    from urllib.parse import quote

    path, line = row.get("path"), row.get("line")
    if not isinstance(path, str) or not path or type(line) is not int or line <= 0:
        return []
    if (
        path.startswith("/")
        or any(c in path for c in "\\:\0")
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or any(not c.isprintable() for c in path)
    ):
        return []
    return [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": quote(path, safe="/")},
                "region": {"startLine": line},
            }
        }
    ]


def _sarif_result(row: dict) -> dict:
    severity = row.get("severity", "INFO")
    severity = severity if isinstance(severity, str) and len(severity) <= 32 else "INFO"
    result = {
        "ruleId": _sarif_rule(row),
        "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}.get(
            severity.upper(), "note"
        ),
        "message": {"text": _sarif_message(row)},
        "properties": {"originalSeverity": severity},
    }
    location = _sarif_location(row)
    if location:
        result["locations"] = location
    identity = [row.get("lane_id"), row.get("finding_id")]
    if all(isinstance(v, str) and v for v in identity):
        raw = json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode()
        result["partialFingerprints"] = {
            "factoryNativeIdentity/v1": hashlib.sha256(raw).hexdigest()
        }
    else:
        raw = json.dumps(result, sort_keys=True, ensure_ascii=True).encode()
        result["partialFingerprints"] = {
            "factoryFinding/v1": hashlib.sha256(raw).hexdigest()
        }
    return result


def _sarif_scan_properties(result: dict, code: int) -> dict:
    coverage = result.get("static_security", {}).get("audit_coverage", {})
    keys = (
        "complete",
        "measurement_state",
        "files_discovered",
        "files_attempted",
        "files_audited",
        "inventory_complete",
        "audit_rate",
    )
    properties = {
        "state": result.get("state", "INVALID"),
        "verdict": result.get("verdict", "INCOMPLETE"),
        "exitCode": code,
        "releaseApproval": False,
        "claimBoundary": "Output adaptation does not independently validate evidence or grant release approval.",
        "staticCoverage": {k: coverage[k] for k in keys if k in coverage},
        "deepLanes": [
            {"measurementId": row.get("measurement_id"), "state": row.get("state")}
            for row in (result.get("deep_audit") or {}).get("lanes", [])
        ],
    }
    scan_hash = result.get("scan_sha256")
    if isinstance(scan_hash, str) and re.fullmatch("[0-9a-f]{64}", scan_hash):
        properties["scanSha256"] = scan_hash
    properties.update(_sarif_native_context(result))
    properties["contractSha256"] = scan_output_contract()["contract_sha256"]
    return properties


def _sarif_native_context(result: dict) -> dict:
    security = result.get("static_security") or {}
    policy = security.get("policy_scopes", {}).get("native_static", {}).get("state")
    properties = {"nativePolicyState": policy} if policy is not None else {}
    native = (result.get("deep_audit") or {}).get("native_domains") or {}
    properties["nativeDomains"] = [
        {
            "measurementId": row.get("measurement_id"),
            "state": row.get("state"),
            **(
                {"sourceCurrent": row["result"]["source_current"]}
                if isinstance(row.get("result"), dict)
                and "source_current" in row["result"]
                else {}
            ),
        }
        for row in native.get("domains", [])
    ]
    return properties


def _scan_execution_successful(result: dict) -> bool:
    """Separate completed findings from an analyzer that could not execute."""
    static = result.get("static_security", {})
    layers = [
        result,
        static,
        static.get("python_ast_security", {}),
        result.get("deep_audit"),
    ]
    return all(
        layer.get("state") not in {"INVALID", "ERROR"}
        and not str(layer.get("schema", "")).endswith(".error.v1")
        and layer.get("audit_coverage", {}).get("measurement_state")
        not in {"invalid", "error", "failed"}
        for layer in layers
        if isinstance(layer, dict)
    )


def _scan_sarif(result: dict, code: int) -> dict:
    rows = [_sarif_result(row) for row in _scan_findings(result)]
    notifications = []
    if result.get("state") != "PASS" or result.get("verdict") != "PASS":
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": "Scan is not PASS; findings or evidence gaps remain. No release approval is granted."
                },
            }
        )
    if any("locations" not in row for row in rows):
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": "Some findings lack a safe known source location; no location or column was inferred."
                },
            }
        )
    invocation = {"executionSuccessful": _scan_execution_successful(result)}
    if notifications:
        invocation["toolExecutionNotifications"] = notifications
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Code Factory",
                        "rules": [
                            {"id": key} for key in sorted({r["ruleId"] for r in rows})
                        ],
                    }
                },
                "results": rows,
                "invocations": [invocation],
                "properties": _sarif_scan_properties(result, code),
            }
        ],
    }


def _read_input(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _first_lap_init(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    result = first_lap.initialize_first_lap(
        workspace,
        mission=args.mission,
        journeys=args.journeys,
        holdouts=args.holdouts,
        overwrite=args.force,
    )
    return result, 0


def _first_lap_status(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    result = first_lap.first_lap_status(workspace)
    code = 0 if result.get("state") in {"INITIALIZED", "NOT_INITIALIZED"} else 1
    return result, code


def _first_lap_calibrate(
    args: Any, workspace: Path, first_lap: Any
) -> tuple[dict, int]:
    result = first_lap.verify_verifier_calibration(
        workspace, _read_input(args.input), strict=args.strict
    )
    code = 0 if result.get("state") == "CALIBRATED" else 1
    return result, code


def _first_lap_incident(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    payload = _read_input(args.input)
    result = first_lap.record_incident(workspace, payload)
    if args.promote:
        result = {
            "recorded": result,
            "promoted": first_lap.promote_incident(workspace, payload),
        }
    return result, 0


def _first_lap_promote(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    return first_lap.promote_incident(workspace, _read_input(args.input)), 0


def _first_lap_holdout(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    result = first_lap.verify_holdout_boundary(
        workspace, _read_input(args.input), strict=args.strict
    )
    code = 0 if result.get("state") == "VERIFIED" else 1
    return result, code


def _first_lap_observe(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    result = first_lap.verify_observed_first_lap(
        _read_input(args.input), strict=args.strict
    )
    code = 0 if result.get("state") == "OBSERVED" else 1
    return result, code


def _first_lap_failure(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    return (
        first_lap.classify_failure(
            args.kind,
            provider=args.provider,
            retry_after_seconds=args.retry_after,
            strict=args.strict,
        ),
        0,
    )


def _first_lap_verify(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    result = first_lap.verify_activation(
        workspace,
        calibration=_read_input(args.calibration),
        holdout=_read_input(args.holdout),
        observed=_read_input(args.observed),
        strict=args.strict,
        persist=args.persist,
    )
    code = 0 if result.get("state") == "READY" else 1
    return result, code


def _execute_first_lap_command(
    args: Any, workspace: Path, first_lap: Any
) -> tuple[dict, int]:
    handlers = {
        "init": _first_lap_init,
        "status": _first_lap_status,
        "calibrate": _first_lap_calibrate,
        "incident": _first_lap_incident,
        "promote": _first_lap_promote,
        "holdout": _first_lap_holdout,
        "observe": _first_lap_observe,
        "failure": _first_lap_failure,
    }
    handler = handlers.get(args.first_lap_cmd, _first_lap_verify)
    return handler(args, workspace, first_lap)


def _first_lap_error(exc: Exception) -> dict[str, Any]:
    return {
        "schema": "factory.first-lap.error.v1",
        "marker": "FIRST_LAP_BLOCKED",
        "code": getattr(exc, "code", "E_FIRST_LAP_INPUT"),
        "message": str(exc),
        "authority": "none",
    }


def _render_first_lap_success(result: dict[str, Any]) -> None:
    print(f"first lap: {result.get('marker', result.get('state', 'READY'))}")
    if result.get("paths"):
        for name, path in result["paths"].items():
            print(f"  {name}: {path}")
    if result.get("retry_allowed") is not None:
        print(f"retry allowed: {result['retry_allowed']}")


def _render_first_lap_result(args: Any, result: dict[str, Any], code: int) -> None:
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif code == 0:
        _render_first_lap_success(result)
    else:
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
