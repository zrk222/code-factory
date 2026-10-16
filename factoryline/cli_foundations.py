"""CLI boundary for architecture, external evidence, journey, and efficiency."""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any

from .failure_guidance import explain_failure


def _script_directory(current, ignored, entries, max_entries, deadline):
    children, suffixes = [], set()
    with os.scandir(current) as stream:
        for entry in stream:
            entries += 1
            if entries > max_entries or time.monotonic() >= deadline:
                raise ValueError("script inventory budget exhausted")
            if entry.name.lower() in ignored:
                continue
            attributes = entry.stat(follow_symlinks=False)
            if entry.is_symlink() or getattr(
                attributes, "st_file_attributes", 0
            ) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
                raise ValueError("linked script inventory entry")
            if entry.is_dir(follow_symlinks=False):
                children.append(Path(entry.path))
            elif entry.is_file(follow_symlinks=False):
                suffixes.add(Path(entry.name).suffix.lower())
    return children, suffixes, entries


def project_script_inventory(
    root: Path,
    *,
    max_entries: int = 100_000,
    max_directories: int = 10_000,
    max_depth: int = 64,
    timeout: float = 5.0,
) -> tuple[set[str], list[Path], bool]:
    """Bound script discovery without traversing generated trees or links."""
    ignored = {
        ".git",
        ".hg",
        ".svn",
        ".factory",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "build",
        "dist",
        "coverage",
        ".next",
        ".nuxt",
        ".cache",
        "target",
    }
    scripts = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
    suffixes: set[str] = set()
    roots: list[Path] = []
    pending = [(Path(root), 0)]
    entries = directories = 0
    deadline = time.monotonic() + timeout
    try:
        while pending:
            current, depth = pending.pop()
            directories += 1
            if (
                directories > max_directories
                or depth > max_depth
                or time.monotonic() >= deadline
            ):
                return suffixes, roots, False
            children, local_suffixes, entries = _script_directory(
                current, ignored, entries, max_entries, deadline
            )
            found = local_suffixes & scripts
            if found:
                suffixes.update(found)
                if len(roots) >= 128:
                    return suffixes, roots, False
                roots.append(current.resolve())
            pending.extend(
                (child, depth + 1) for child in sorted(children, reverse=True)
            )
    except (OSError, ValueError):
        return suffixes, roots, False
    return suffixes, roots, time.monotonic() < deadline


def emit_version(as_json: bool) -> int:
    """Format the CLI's version response from the shared provenance receipt."""
    from .provenance import provenance

    payload = provenance()
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if as_json
        else f"factory {payload['version']}"
    )
    return 0


def cli_command(name: str) -> str:
    """Prefer the launcher's script directory over an ambient PATH lookup."""
    script_dirs = [
        Path(sys.argv[0]).resolve().parent,
        Path(sys.executable).resolve().parent,
    ]
    for scripts in dict.fromkeys(script_dirs):
        for suffix in (".exe", ".cmd", ""):
            candidate = scripts / f"{name}{suffix}"
            if candidate.exists():
                return str(candidate)
    return name


def add_parser(sub: Any) -> None:
    """Register the foundational proof and architecture command families."""
    version = sub.add_parser("version", help="show package provenance")
    version.add_argument("--json", action="store_true")
    architecture = sub.add_parser(
        "architecture", help="measure architecture debt and enforce growth budgets"
    )
    architecture_sub = architecture.add_subparsers(
        required=True, dest="architecture_cmd"
    )
    architecture_health = architecture_sub.add_parser(
        "health",
        help="report documentation, CLI, module-surface, and release-cadence health",
    )
    architecture_health.add_argument("--root", default=".")
    architecture_health.add_argument(
        "--policy", help="policy JSON; defaults to architecture-policy.json below root"
    )
    architecture_health.add_argument(
        "--strict",
        action="store_true",
        help="treat existing architecture debt as blocking",
    )
    architecture_health.add_argument("--json", action="store_true")

    external = sub.add_parser(
        "external", help="import and compare offline external runtime evidence"
    )
    external_sub = external.add_subparsers(required=True, dest="external_cmd")
    external_import = external_sub.add_parser(
        "import", help="verify one provider bundle and write an observed-only receipt"
    )
    external_import.add_argument(
        "bundle",
        help="workspace-contained factory.external-runtime-bundle.v1 JSON path",
    )
    external_import.add_argument("--root", default=".")
    external_import.add_argument(
        "--provider", required=True, help="declared adapter id, for example testsprite"
    )
    external_import.add_argument(
        "--out", help="receipt path below .factory/external-evidence/"
    )
    external_import.add_argument("--json", action="store_true")
    external_diff = external_sub.add_parser(
        "diff", help="compare two verified receipts without provider execution"
    )
    external_diff.add_argument("left", help="left receipt path")
    external_diff.add_argument("right", help="right receipt path")
    external_diff.add_argument("--root", default=".")
    external_diff.add_argument("--json", action="store_true")

    journey = sub.add_parser(
        "journey",
        help="prove runtime journeys, stateful workflows, failures, and bounded healing",
    )
    journey_sub = journey.add_subparsers(required=True, dest="journey_cmd")
    journey_reality = journey_sub.add_parser(
        "reality", help="compare declared and observed journey graphs without inference"
    )
    journey_reality.add_argument(
        "declaration", help="factory.journey-declaration.v1 JSON path"
    )
    journey_reality.add_argument(
        "observation", help="factory.journey-observation.v1 JSON path"
    )
    journey_reality.add_argument("--root", default=".")
    journey_reality.add_argument(
        "--out", help="receipt path below .factory/journey-proof/"
    )
    journey_reality.add_argument("--json", action="store_true")
    journey_capsule = journey_sub.add_parser(
        "capsule",
        help="bind a failed step and adjacent evidence into JSON and Markdown",
    )
    journey_capsule.add_argument(
        "input", help="factory.failure-capsule-input.v1 JSON path"
    )
    journey_capsule.add_argument("--root", default=".")
    journey_capsule.add_argument(
        "--out", help="receipt path below .factory/journey-proof/"
    )
    journey_capsule.add_argument("--json", action="store_true")
    journey_workflow = journey_sub.add_parser(
        "workflow-proof", help="prove state flow, cleanup, and idempotency"
    )
    journey_workflow.add_argument(
        "input", help="factory.stateful-workflow-input.v1 JSON path"
    )
    journey_workflow.add_argument("--root", default=".")
    journey_workflow.add_argument(
        "--out", help="receipt path below .factory/journey-proof/"
    )
    journey_workflow.add_argument("--json", action="store_true")
    journey_healing = journey_sub.add_parser(
        "heal-verify", help="challenge a repair under human or supervised-auto review"
    )
    journey_healing.add_argument(
        "input", help="factory.proof-gated-healing-input.v1 JSON path"
    )
    journey_healing.add_argument("--root", default=".")
    journey_healing.add_argument(
        "--out", help="receipt path below .factory/journey-proof/"
    )
    journey_healing.add_argument("--timeout-seconds", type=int, default=300)
    journey_healing.add_argument("--json", action="store_true")
    journey_status = journey_sub.add_parser(
        "status", help="read verified local Journey Proof receipts without execution"
    )
    journey_status.add_argument("--root", default=".")
    journey_status.add_argument("--json", action="store_true")
    journey_evaluate = journey_sub.add_parser(
        "evaluate-trace", help="evaluate a hash-bound local trace-evaluation request"
    )
    journey_evaluate.add_argument("request", help="trace-evaluation request JSON path")
    journey_evaluate.add_argument("--request-sha256", required=True)
    journey_evaluate.add_argument("--root", default=".")
    journey_evaluate.add_argument("--json", action="store_true")

    efficiency = sub.add_parser(
        "efficiency", help="compile and verify bounded, cacheable context packets"
    )
    efficiency_sub = efficiency.add_subparsers(dest="efficiency_cmd", required=True)
    efficiency_pack = efficiency_sub.add_parser(
        "pack", help="build a read-only bounded context packet"
    )
    efficiency_pack.add_argument(
        "--manifest", required=True, help="JSON request manifest"
    )
    efficiency_pack.add_argument("--root", default=".")
    efficiency_pack.add_argument("--out")
    efficiency_pack.add_argument("--json", action="store_true")
    efficiency_select = efficiency_sub.add_parser(
        "select", help="rank explicit task candidates and build progressive context"
    )
    efficiency_select.add_argument(
        "--manifest", required=True, help="bounded candidate-selection JSON manifest"
    )
    efficiency_select.add_argument("--root", default=".")
    efficiency_select.add_argument("--out")
    efficiency_select.add_argument("--json", action="store_true")
    efficiency_record = efficiency_sub.add_parser(
        "record", help="evaluate and store operator-supplied paired observations"
    )
    efficiency_record.add_argument(
        "--manifest", required=True, help="paired observation JSON"
    )
    efficiency_record.add_argument("--root", default=".")
    efficiency_record.add_argument("--json", action="store_true")
    efficiency_verify = efficiency_sub.add_parser(
        "verify", help="verify packet and source hashes"
    )
    efficiency_verify.add_argument("packet")
    efficiency_verify.add_argument("--root", default=".")
    efficiency_verify.add_argument("--json", action="store_true")
    efficiency_status = efficiency_sub.add_parser(
        "status", help="show bounded packet/cache metadata"
    )
    efficiency_status.add_argument("--root", default=".")
    efficiency_status.add_argument("--json", action="store_true")

    shard_build = efficiency_sub.add_parser(
        "shard-build", help="build an immutable source-bound context shard candidate"
    )
    shard_build.add_argument(
        "--manifest", required=True, help="bounded shard request JSON"
    )
    shard_build.add_argument("--root", default=".")
    shard_build.add_argument("--json", action="store_true")
    shard_validate = efficiency_sub.add_parser(
        "shard-validate", help="validate candidate provenance and freshness"
    )
    shard_validate.add_argument(
        "candidate", help="workspace-relative candidate JSON path"
    )
    shard_validate.add_argument(
        "--accepted", help="bounded workspace-relative accepted-shards JSON list"
    )
    shard_validate.add_argument("--root", default=".")
    shard_validate.add_argument("--json", action="store_true")
    shard_review = efficiency_sub.add_parser(
        "shard-review", help="record an explicit unauthenticated caller review"
    )
    shard_review.add_argument(
        "candidate", help="workspace-relative candidate JSON path"
    )
    shard_review.add_argument(
        "--decision", required=True, choices=("accept", "reject", "defer")
    )
    shard_review.add_argument("--reviewer-id", required=True)
    shard_review.add_argument("--review-basis", required=True)
    shard_review.add_argument("--root", default=".")
    shard_review.add_argument("--json", action="store_true")


def _run_architecture(args: Any) -> int:
    from .architecture_health import (
        ArchitectureHealthError,
        evaluate_architecture_health,
    )

    try:
        result = evaluate_architecture_health(
            Path(args.root),
            Path(args.policy) if args.policy else None,
            strict=args.strict,
        )
    except (
        ArchitectureHealthError,
        OSError,
        UnicodeDecodeError,
        ValueError,
    ) as exc:
        error = {
            "schema": "factory.architecture-health-error.v1",
            "status": "failed",
            "code": getattr(exc, "code", "E_ARCHITECTURE_HEALTH"),
            "message": str(exc),
        }
        print(json.dumps(error, indent=2, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result.get("decision") == "BLOCKED" else 0


def _external_result(args: Any) -> dict[str, Any]:
    from .external_evidence import (
        diff_external_runtime_receipts,
        import_external_runtime_bundle,
    )

    if args.external_cmd == "import":
        return import_external_runtime_bundle(
            Path(args.root),
            Path(args.bundle),
            args.provider,
            Path(args.out) if args.out else None,
        )
    return diff_external_runtime_receipts(
        Path(args.root), Path(args.left), Path(args.right)
    )


def _run_external(args: Any) -> int:
    from .external_evidence import ExternalEvidenceError

    try:
        result = _external_result(args)
    except ExternalEvidenceError as exc:
        print(
            json.dumps(
                {
                    "schema": "factory.workflow_error.v1",
                    "status": "failed",
                    "code": exc.code,
                    "message": exc.message,
                    "marker": exc.code,
                    "failure": explain_failure(exc.code, exc.message),
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.external_cmd == "diff" and result.get("comparable") is not True:
        return 1
    return 0


def _journey_result(args: Any, root: Path) -> dict[str, Any]:
    from .journey_proof import (
        compile_reality_graph,
        create_failure_capsule,
        journey_proof_status,
        verify_proof_gated_healing,
        verify_stateful_workflow,
    )

    command = args.journey_cmd
    if command == "evaluate-trace":
        from .analysis_evidence import evaluate_spans_file

        return evaluate_spans_file(root, Path(args.request), args.request_sha256)
    output_path = getattr(args, "out", None)
    output = Path(output_path) if output_path else None
    if command == "reality":
        return compile_reality_graph(
            root, Path(args.declaration), Path(args.observation), output
        )
    if command == "capsule":
        return create_failure_capsule(root, Path(args.input), output)
    if command == "workflow-proof":
        return verify_stateful_workflow(root, Path(args.input), output)
    if command == "heal-verify":
        return verify_proof_gated_healing(
            root, Path(args.input), output, args.timeout_seconds
        )
    return journey_proof_status(root)


def _run_journey(args: Any) -> int:
    from .analysis_evidence import AnalysisEvidenceError
    from .journey_proof import JourneyProofError

    try:
        result = _journey_result(args, Path(args.root))
    except JourneyProofError as exc:
        print(
            json.dumps(
                {
                    "schema": "factory.workflow_error.v1",
                    "status": "failed",
                    "code": exc.code,
                    "message": str(exc),
                    "marker": exc.code,
                    "failure": explain_failure(exc.code, str(exc)),
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    except AnalysisEvidenceError as exc:
        print(
            json.dumps(
                {
                    "schema": "factory.trace-evaluation.error.v1",
                    "status": "BLOCKED",
                    "code": exc.code,
                    "message": str(exc),
                    "marker": exc.code,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.journey_cmd == "reality" and result.get("decision") != "matched":
        return 1
    if args.journey_cmd in {"workflow-proof", "heal-verify"} and result.get(
        "decision"
    ) not in {"passed", "admissible_for_human_review"}:
        return 1
    if args.journey_cmd == "evaluate-trace":
        state = result.get(
            "status", result.get("state", result.get("decision", result.get("verdict")))
        )
        if not isinstance(state, str) or state.upper() not in {
            "PASS",
            "PASSED",
            "SUCCESS",
        }:
            return 1
    return 0


def _efficiency_result(args: Any, root: Path) -> tuple[dict[str, Any], int]:
    from .context_efficiency import (
        build_context_packet,
        build_selected_context_packet,
        context_efficiency_status,
        record_context_experiment,
        verify_context_packet,
    )

    if args.efficiency_cmd in {"shard-build", "shard-validate", "shard-review"}:
        return _efficiency_shard_result(args, root)
    if args.efficiency_cmd in {"pack", "select", "record"}:
        with Path(args.manifest).open("rb") as stream:
            raw = stream.read(1_000_001)
        if len(raw) > 1_000_000:
            from .context_efficiency import ContextEfficiencyError

            raise ContextEfficiencyError("E_INPUT_BOUNDARY", "manifest exceeds 1 MB")
        manifest = json.loads(raw.decode("utf-8-sig"))
    if args.efficiency_cmd == "pack":
        return (
            build_context_packet(root, manifest, Path(args.out) if args.out else None),
            0,
        )
    if args.efficiency_cmd == "select":
        return (
            build_selected_context_packet(
                root, manifest, Path(args.out) if args.out else None
            ),
            0,
        )
    if args.efficiency_cmd == "record":
        return record_context_experiment(root, manifest), 0
    if args.efficiency_cmd == "verify":
        result = verify_context_packet(root, Path(args.packet))
        return result, 0 if result.get("valid") is True else 1
    return context_efficiency_status(root), 0


def _efficiency_shard_result(args: Any, root: Path) -> tuple[dict[str, Any], int]:
    from .context_efficiency import (
        MAX_SHARD_ARTIFACT_BYTES,
        ContextEfficiencyError,
        build_context_shard_candidate,
        review_context_shard_candidate,
        validate_context_shard_candidate,
    )

    if args.efficiency_cmd == "shard-build":
        raw, _ = _read_shard_cli_input(root, args.manifest, "manifest", 1_000_000)
        request = json.loads(raw.decode("utf-8-sig"))
        fields = {
            "schema",
            "packet_path",
            "shard_type",
            "claims",
            "retained_records",
            "expires_at",
        }
        if (
            not isinstance(request, dict)
            or set(request) != fields
            or request.get("schema") != "factory.context-shard-request.v1"
        ):
            raise ContextEfficiencyError(
                "E_SHARD_FIELDS",
                "manifest must use the exact context-shard request schema",
            )
        if not isinstance(request["packet_path"], str):
            raise ContextEfficiencyError(
                "E_SHARD_FIELDS", "packet_path must be workspace-relative"
            )
        if (
            not isinstance(request["shard_type"], str)
            or not isinstance(request["claims"], list)
            or not isinstance(request["retained_records"], dict)
            or not isinstance(request["expires_at"], str)
        ):
            raise ContextEfficiencyError(
                "E_SHARD_FIELDS", "manifest field types are invalid"
            )
        return build_context_shard_candidate(
            root,
            Path(request["packet_path"]),
            request["shard_type"],
            request["claims"],
            request["retained_records"],
            request["expires_at"],
        ), 0

    candidate_raw, relative = _read_shard_cli_input(
        root, args.candidate, "candidate path", MAX_SHARD_ARTIFACT_BYTES
    )
    candidate = json.loads(candidate_raw.decode("utf-8"))
    if not isinstance(candidate, dict):
        raise ContextEfficiencyError(
            "E_SHARD_FIELDS", "candidate artifact must be an object"
        )
    candidate["artifact_path"] = relative
    if args.efficiency_cmd == "shard-review":
        return (
            review_context_shard_candidate(
                root,
                candidate,
                args.decision,
                args.reviewer_id,
                args.review_basis,
            ),
            0,
        )
    accepted_shards = ()
    if args.accepted:
        accepted_raw, _ = _read_shard_cli_input(
            root, args.accepted, "accepted shards", 1_000_000
        )
        accepted_shards = json.loads(accepted_raw.decode("utf-8"))
        if not isinstance(accepted_shards, list):
            raise ContextEfficiencyError(
                "E_SHARD_FIELDS", "accepted shards input must be a JSON list"
            )
    result = validate_context_shard_candidate(
        root, relative, accepted_shards=accepted_shards
    )
    return result, 0 if result.get("valid") is True else 1


def _read_shard_cli_input(
    root: Path, raw_path: str, field: str, limit: int
) -> tuple[bytes, str]:
    """Read one regular, workspace-contained shard input without path disclosure."""
    from .context_efficiency import (
        ContextEfficiencyError,
        _has_reparse_ancestor,
        _read_bounded,
        _shard_relative_path,
    )

    path, relative = _shard_relative_path(root, raw_path, field)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or _has_reparse_ancestor(path):
            raise ContextEfficiencyError(
                "E_PATH_INPUT", f"{field} must be a regular workspace file"
            )
        return _read_bounded(path, limit), relative
    except ContextEfficiencyError:
        raise
    except OSError as exc:
        raise ContextEfficiencyError(
            "E_PATH_INPUT", f"{field} cannot be read as a bounded workspace file"
        ) from exc


def _run_efficiency(args: Any) -> int:
    from .context_efficiency import ContextEfficiencyError

    try:
        root = Path(args.root)
        if args.efficiency_cmd in {"shard-build", "shard-validate", "shard-review"}:
            root = root.absolute()
        else:
            root = root.resolve()
        result, code = _efficiency_result(args, root)
    except (
        ContextEfficiencyError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        result = {
            "schema": "factory.context-efficiency-error.v1",
            "marker": "CONTEXT_EFFICIENCY_REFUSED",
            "code": getattr(exc, "code", "E_CONTEXT_INPUT"),
            "message": getattr(exc, "message", str(exc)),
        }
        code = 2
    _render_efficiency(result, code, args)
    return code


def _render_efficiency(result: dict[str, Any], code: int, args: Any) -> None:
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, sort_keys=True))
    elif code == 0:
        print(result.get("marker", result.get("state", "CONTEXT_EFFICIENCY_OK")))
        print(
            "authority   : bounded local context metadata only; no execution, approval, repair, release, publication, or credentials"
        )
    else:
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)


def run(args: Any) -> int:
    """Dispatch one foundational command after parser selection."""
    if args.cmd == "architecture":
        return _run_architecture(args)
    if args.cmd == "external":
        return _run_external(args)
    if args.cmd == "journey":
        return _run_journey(args)
    return _run_efficiency(args)
