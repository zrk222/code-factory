"""Bounded local input primitives for non-authoritative deep analysis evidence."""

from __future__ import annotations

import hashlib  # noqa: F401
import importlib
import json
import os
import re  # noqa: F401
import subprocess
import stat
import threading  # noqa: F401
import uuid
import tempfile
import time
import tokenize  # noqa: F401
from collections import Counter
from pathlib import Path, PureWindowsPath
from urllib.parse import unquote

from .runtime_audit_common import (
    RuntimeAuditError,
    canonical_bytes,
    exact_keys,  # noqa: F401
    require_digest,
    require_int,  # noqa: F401
    require_str,
    sha256_bytes,
)

LIMIT = 10_000_000
NATIVE_COVERAGE_LIMIT = 8 * 1024 * 1024
NATIVE_LEDGER_LIMIT = NATIVE_COVERAGE_LIMIT
NATIVE_SOURCE_MAP_LIMIT = NATIVE_COVERAGE_LIMIT
NATIVE_ACCOUNTING_LIMIT = NATIVE_COVERAGE_LIMIT


def digest(value: object) -> str:
    """Fingerprint normalized JSON using the existing canonical receipt encoding without assigning any authority."""
    return sha256_bytes(canonical_bytes(value))


def relative_path(value: object) -> str:
    """Require a canonical workspace path, rejecting ambiguous URI, Windows and traversal spellings."""
    text = require_str(value, "path", maximum=512)
    parts = text.split("/")
    forbidden = ("\\", ":", "?", "#")
    if any(char in text for char in forbidden) or unquote(text) != text:
        raise RuntimeAuditError("E_PATH_ESCAPE", "noncanonical path")
    if any(
        ord(char) < 32
        or 0x7F <= ord(char) <= 0x9F
        or char
        in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200b\u200c\u200d\ufeff"
        for char in text
    ):
        raise RuntimeAuditError("E_PATH_ESCAPE", "control characters in path")
    if PureWindowsPath(text).drive or any(part in {"", ".", ".."} for part in parts):
        raise RuntimeAuditError("E_PATH_ESCAPE", "path must be workspace-relative")
    if any(
        part.endswith((" ", ".")) or PureWindowsPath(part).is_reserved()
        for part in parts
    ):
        raise RuntimeAuditError("E_PATH_ESCAPE", "ambiguous Windows path")
    return text


def local_file(root: Path, value: object) -> Path:
    """Resolve one regular workspace file while rejecting symlinks and Windows reparse points throughout."""
    root = Path(root).resolve()
    candidate = root
    for part in relative_path(value).split("/"):
        candidate = candidate / part
        try:
            info = candidate.lstat()
        except OSError as exc:
            raise RuntimeAuditError(
                "E_SOURCE_MISSING", "regular file required"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeAuditError("E_PATH_ESCAPE", "linked evidence is not supported")
    candidate.resolve().relative_to(root)
    if not candidate.is_file():
        raise RuntimeAuditError("E_SOURCE_MISSING", "regular file required")
    return candidate


def bound_bytes(root: Path, binding: dict) -> bytes:
    """Read at most the evidence byte budget and verify its caller-supplied SHA-256 binding."""
    expected = require_digest(binding["sha256"], "sha256")
    path = local_file(root, binding["path"])
    with path.open("rb") as stream:
        before = path.stat()
        raw = stream.read(LIMIT + 1)
        after = path.stat()
    if len(raw) > LIMIT:
        raise RuntimeAuditError("E_REPORT_SIZE", "evidence exceeds byte budget")
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise RuntimeAuditError("E_INPUT_CHANGED", "evidence changed during read")
    if sha256_bytes(raw) != expected:
        raise RuntimeAuditError("E_REPORT_DRIFT", "evidence hash mismatch")
    return raw


def _object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeAuditError("E_DUPLICATE_FIELD", "duplicate JSON key")
        result[key] = value
    return result


def _finite(value: str) -> None:
    raise RuntimeAuditError("E_NONFINITE", "non-finite JSON number")


def strict_json(raw: bytes) -> dict:
    """Decode bounded JSON, rejecting duplicate fields, nonfinite values and excessive parser recursion."""
    if len(raw) > LIMIT:
        raise RuntimeAuditError("E_REPORT_SIZE", "JSON exceeds byte budget")
    try:
        value = json.loads(raw, object_pairs_hook=_object, parse_constant=_finite)
        canonical_bytes(value)  # Reject exponent overflow such as 1e999, too.
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, RuntimeAuditError):
            raise
        raise RuntimeAuditError("E_REPORT_JSON", "invalid bounded JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeAuditError("E_REPORT_JSON", "object required")
    return value


# Execution inventory is a separate versioned contract; v1 signed intake keeps
# its original bounds and semantics.
INVENTORY_LIMIT = 50_000
SOURCE_LIMIT = 16 * 1024 * 1024
SNAPSHOT_LIMIT = 1024 * 1024 * 1024
_GENERATED_FACTORY_PREFIXES = (
    ".factory/deep-runs/",
    ".factory/review-evidence/",
    ".factory/scopes/",
    ".factory/repair-approvals/",
    ".factory/repair-attempts/",
)


def _generated_factory_path(name: str) -> bool:
    return (
        name == ".factory/candidate.diff"
        or name.startswith(_GENERATED_FACTORY_PREFIXES)
        or re.fullmatch(r"\.factory/ops/lifecycle/[0-9a-f]{32}\.json", name) is not None
    )


LANGUAGES = {
    "python": ".py .pyi",
    "javascript": ".js .jsx .mjs .cjs",
    "typescript": ".ts .tsx .mts .cts",
    "java": ".java",
    "kotlin": ".kt .kts",
    "go": ".go",
    "rust": ".rs",
    "swift": ".swift",
    "c": ".c .h",
    "cpp": ".cpp .cc .cxx .hpp",
    "csharp": ".cs",
    "ruby": ".rb",
    "php": ".php",
    "shell": ".sh .bash .zsh",
    "powershell": ".ps1 .psm1 .psd1",
    "web": ".html .htm .vue .svelte .css .scss",
    "configuration": ".json .jsonc .yml .yaml .toml .ini .cfg .xml .gradle .tf .tfvars .properties",
    "dependency": ".lock .sum",
    "notebook": ".ipynb",
    "data": ".md .rst .txt .adoc .csv .tsv .png .jpg .jpeg .gif .ico .webp .pdf .woff .woff2 .ttf .mp4 .wav .mp3",
    "document-code": ".svg",
}


def _git_names(root: Path, tracked: bool, *, ignored: bool = False) -> set[str]:
    from .runtime_audit_process import run_bounded_command

    with tempfile.TemporaryDirectory(prefix="factory-inventory-") as scratch:
        output = Path(scratch) / "paths"
        argv = ["git", "-c", "core.fsmonitor=false", "ls-files", "-z"]
        argv += ["--cached"] if tracked else ["--others", "--exclude-standard"]
        if ignored:
            argv += ["--ignored"]
        facts = run_bounded_command(argv, root, 30, Path(scratch), stdout_path=output)
        if (
            facts["exit_code"] != 0
            or facts["output_limit_exceeded"]
            or not facts["cleanup_confirmed"]
        ):
            raise RuntimeAuditError(
                "E_INVENTORY_LIMIT", "Git inventory failed or exceeded bounds"
            )
        return set(output.read_bytes().decode("utf-8", errors="strict").split("\0")) - {
            ""
        }


def _git_paths(root: Path) -> list[str]:
    tracked, untracked = _git_names(root, True), _git_names(root, False)
    # Generated state is excluded only when untracked. Tracked files never vanish.
    generated = {name for name in untracked if _generated_factory_path(name)}
    return sorted(tracked | (untracked - generated))


def source_language(name: str, raw: bytes) -> str:
    """Classify inputs without treating unknown executable formats as covered."""
    suffix = Path(name).suffix.lower()
    base = Path(name).name.lower()
    if base in {"dockerfile", "makefile", "justfile", "procfile"}:
        return "configuration"
    if base in {
        "requirements.txt",
        "poetry.lock",
        "uv.lock",
        "package-lock.json",
        "yarn.lock",
        "go.sum",
        "cargo.lock",
    }:
        return "dependency"
    if raw.startswith(b"#!"):
        first = raw.split(b"\n", 1)[0].lower()
        for language, marker in (
            ("python", b"python"),
            ("javascript", b"node"),
            ("shell", b"sh"),
        ):
            if marker in first:
                return language
        return "unknown"
    for language, suffixes in LANGUAGES.items():
        if suffix in suffixes.split():
            return language
    if base in {
        "license",
        "notice",
        "authors",
        "codeowners",
        ".gitignore",
        ".gitattributes",
        ".dockerignore",
        ".editorconfig",
    }:
        return "data"
    return "unknown"


def _source_bytes(root: Path, name: str) -> tuple[bytes, int]:
    source = local_file(root, name)
    with source.open("rb") as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read(SOURCE_LIMIT + 1)
        after = os.fstat(stream.fileno())
    current = local_file(root, name).stat()

    def identity(value):
        return value.st_ino, value.st_size, value.st_mtime_ns

    if identity(before) != identity(after) or identity(after) != identity(current):
        raise RuntimeAuditError("E_INPUT_CHANGED", "source changed during inventory")
    if len(raw) > SOURCE_LIMIT:
        raise RuntimeAuditError("E_SOURCE_SIZE", "source exceeds file byte budget")
    return raw, stat.S_IMODE(before.st_mode)


def _prepare_snapshot(root: Path, snapshot: Path | None) -> Path | None:
    if snapshot is None:
        return None
    snapshot = Path(snapshot).absolute()
    for component in (snapshot, *snapshot.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeAuditError(
                "E_SNAPSHOT_PATH", "snapshot ancestors must not be linked"
            )
    if (
        snapshot.is_symlink()
        or getattr(snapshot.lstat(), "st_file_attributes", 0) & 0x400
        or any(snapshot.iterdir())
    ):
        raise RuntimeAuditError(
            "E_SNAPSHOT_PATH", "snapshot must be a fresh empty regular directory"
        )
    snapshot = snapshot.resolve()
    if snapshot == root or root in snapshot.parents:
        raise RuntimeAuditError(
            "E_SNAPSHOT_PATH", "snapshot must be outside the source tree"
        )
    return snapshot


def _candidate_paths(root: Path, gaps: list[dict]) -> tuple[list[str], list[str]]:
    try:
        paths = _git_paths(root)
        ignored = sorted(
            name
            for name in _git_names(root, False, ignored=True)
            if not _generated_factory_path(name)
        )
    except (OSError, subprocess.SubprocessError, UnicodeError, RuntimeAuditError):
        paths, ignored = [], []
        gaps.append(
            {
                "code": "GIT_INVENTORY_FAILED",
                "path": ".",
                "action": "Restore a readable Git worktree and rerun inventory.",
            }
        )
    for name in ignored:
        gaps.append(
            {
                "code": "IGNORED_INPUT_SCOPE",
                "path": name,
                "action": "Move non-product caches outside the audited checkout; include every build/runtime input as tracked or nonignored source.",
            }
        )
    if not paths:
        gaps.append(
            {
                "code": "EMPTY_CANDIDATE",
                "path": ".",
                "action": "Include the product source before requesting a depth assessment.",
            }
        )
    if len(paths) > INVENTORY_LIMIT:
        gaps.append(
            {
                "code": "INVENTORY_LIMIT",
                "path": ".",
                "action": "Partition the declared product into explicitly bound targets; inventory was truncated.",
            }
        )
    return paths, ignored


def _capture_inventory_source(
    root: Path, name: str, seen: set[str], total: list[int]
) -> tuple[dict, bytes, int]:
    relative_path(name)
    if _generated_factory_path(name):
        raise RuntimeAuditError(
            "E_RESERVED_SOURCE",
            "tracked source collides with generated FactoryLine state",
        )
    if name.casefold() in seen:
        raise RuntimeAuditError("E_CASE_COLLISION", "case-colliding source paths")
    seen.add(name.casefold())
    if total[0] >= SNAPSHOT_LIMIT:
        raise RuntimeAuditError("E_SNAPSHOT_SIZE", "snapshot total budget exhausted")
    raw, mode = _source_bytes(root, name)
    total[0] += len(raw)
    if total[0] > SNAPSHOT_LIMIT:
        raise RuntimeAuditError("E_SNAPSHOT_SIZE", "snapshot exceeds total byte budget")
    item = {
        "path": name,
        "sha256": sha256_bytes(raw),
        "bytes": len(raw),
        "mode": mode,
        "language": source_language(name, raw),
    }
    return item, raw, mode


def _copy_snapshot_file(
    snapshot: Path, name: str, raw: bytes, mode: int, expected_digest: str
) -> None:
    target = snapshot / name
    current = snapshot
    for part in relative_path(name).split("/")[:-1]:
        current /= part
        current.mkdir(exist_ok=True)
        info = current.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise RuntimeAuditError("E_SNAPSHOT_PATH", "linked snapshot parent")
    with target.open("xb") as stream:
        stream.write(raw)
    target.chmod(mode)
    if sha256_bytes(target.read_bytes()) != expected_digest:
        raise RuntimeAuditError(
            "E_SNAPSHOT_DRIFT", "snapshot copy differs from captured source"
        )


def _inventory_candidate_file(
    root: Path,
    name: str,
    seen: set[str],
    total: list[int],
    snapshot: Path | None,
    gaps: list[dict],
) -> dict:
    item = {"path": name, "sha256": None, "bytes": None, "language": "unknown"}
    try:
        captured, raw, mode = _capture_inventory_source(root, name, seen, total)
        item.update(captured)
        if snapshot is not None:
            _copy_snapshot_file(snapshot, name, raw, mode, item["sha256"])
        if item["language"] == "unknown":
            gaps.append(
                {
                    "code": "UNCLASSIFIED_INPUT",
                    "path": name,
                    "action": "Assign and validate a supported analyzer for this input; do not silently exclude it.",
                }
            )
    except (OSError, ValueError, RuntimeAuditError) as exc:
        gaps.append(
            {
                "code": getattr(exc, "code", "SOURCE_UNREADABLE"),
                "path": name,
                "action": "Restore regular readable source inside the worktree, then rerun inventory.",
            }
        )
    return item


def _ignored_names(root: Path) -> list[str]:
    return sorted(
        name
        for name in _git_names(root, False, ignored=True)
        if not _generated_factory_path(name)
    )


def _verify_source_files(root: Path, files: list[dict], gaps: list[dict]) -> None:
    for item in files:
        if item["sha256"] is not None:
            raw, mode = _source_bytes(root, item["path"])
            if sha256_bytes(raw) != item["sha256"] or mode != item.get("mode"):
                gaps.append(
                    {
                        "code": "SOURCE_DRIFT",
                        "path": item["path"],
                        "action": "Stop concurrent edits and recapture the candidate.",
                    }
                )


def _verify_inventory_stability(
    root: Path,
    paths: list[str],
    ignored: list[str],
    files: list[dict],
    gaps: list[dict],
) -> None:
    try:
        if paths != _git_paths(root):
            gaps.append(
                {
                    "code": "INVENTORY_DRIFT",
                    "path": ".",
                    "action": "Retry against an immutable source snapshot.",
                }
            )
        if ignored != _ignored_names(root):
            gaps.append(
                {
                    "code": "IGNORED_SCOPE_DRIFT",
                    "path": ".",
                    "action": "Retry against stable source and ignored-input scope.",
                }
            )
        _verify_source_files(root, files, gaps)
    except (OSError, subprocess.SubprocessError, UnicodeError, RuntimeAuditError):
        gaps.append(
            {
                "code": "INVENTORY_RECHECK_FAILED",
                "path": ".",
                "action": "Restore Git inventory access and rerun.",
            }
        )


def _inventory_result(
    paths: list[str], files: list[dict], gaps: list[dict], ignored: list[str]
) -> dict:
    return {
        "schema": "factory.deep-inventory.v1",
        "state": "INCOMPLETE" if gaps else "COMPLETE",
        "candidate_sha256": digest(files),
        "files": files,
        "gaps": gaps,
        "discovered_paths": len(paths),
        "accounted_paths": len(files),
        "languages": dict(sorted(Counter(item["language"] for item in files).items())),
        "ignored_paths": ignored,
        "scope": "tracked and nonignored untracked inputs; ignored paths are explicit gaps",
        "reserved_output_boundary": {
            "path": ".factory/deep-runs/",
            "reason": "Only untracked coordinator state is excluded; tracked collisions block and the snapshot never includes this directory.",
        },
        "authority": "none",
    }


def inventory_candidate(root: Path, snapshot: Path | None = None) -> dict:
    """Account for tracked/dirty/untracked inputs; optionally copy a private snapshot."""
    root = Path(root).resolve()
    snapshot = _prepare_snapshot(root, snapshot)
    files, gaps, seen, total = [], [], set(), [0]
    paths, ignored = _candidate_paths(root, gaps)
    for name in paths[:INVENTORY_LIMIT]:
        files.append(_inventory_candidate_file(root, name, seen, total, snapshot, gaps))
    _verify_inventory_stability(root, paths, ignored, files, gaps)
    return _inventory_result(paths, files, gaps, ignored)


def run_directory(root: Path, run_id: str, *, create: bool = False) -> Path:
    """Keep execution state within a regular, non-linked private directory."""
    if len(run_id) != 32 or any(char not in "0123456789abcdef" for char in run_id):
        raise RuntimeAuditError(
            "E_RUN_ID", "run ID must be 32 lowercase hex characters"
        )
    current = Path(root).resolve()
    for part in (".factory", "deep-runs", run_id):
        current /= part
        if create:
            current.mkdir(mode=0o700, exist_ok=True)
        info = current.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise RuntimeAuditError("E_RUN_PATH", "run state must not contain links")
    return current


def write_run_json(directory: Path, name: str, value: dict) -> None:
    """Atomically replace a local state artifact; hashes are integrity, not identity."""
    target = Path(directory) / relative_path(name)
    if "/" in name:
        raise RuntimeAuditError("E_RUN_PATH", "state name must be a basename")
    if target.exists() or target.is_symlink():
        local_file(directory, name)
    body = {**value, "sha256": digest(value)}
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(canonical_bytes(body))
            stream.flush()
            os.fsync(stream.fileno())
        for attempt in range(5):
            try:
                os.replace(temporary, target)
                break
            except PermissionError:
                # Windows indexers may transiently hold the destination open.
                if os.name != "nt" or attempt == 4:
                    raise
                time.sleep(0.02 * (attempt + 1))
    finally:
        temporary.unlink(missing_ok=True)


def read_run_json(directory: Path, name: str) -> dict:
    """Read bounded local run evidence and verify its integrity digest."""
    source = local_file(directory, name)
    with source.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    value = strict_json(raw)
    expected = value.pop("sha256", None)
    if expected != digest(value):
        raise RuntimeAuditError("E_RUN_INTEGRITY", "run state digest mismatch")
    return value


if __name__ == "__main__":
    raise SystemExit(importlib.import_module(".deep_audit", __package__).adapter_main())

_MOVED_EXPORT_MODULES = {
    "contract": "deep_audit_contract",
    "sarif": "deep_audit_sarif",
    "attestation": "deep_audit_attestation",
    "loop": "deep_audit_loop",
    "deep_audit": "deep_audit",
}
_MOVED_EXPORTS = {
    "contract": frozenset(
        """
        _adapter_argv_shape
        _adapter_command_failed
        _adapter_command_shape
        _adapter_commands
        _adapter_contract_parts
        _adapter_exit_shape
        _adapter_invocation
        _adapter_output_paths
        _adapter_profile
        _adapter_source_files
        _adapter_sources
        _bounded_json_bytes
        _codeql_query_ids
        _codeql_query_preflight
        _codeql_resolved_queries
        _codeql_selection_ids
        _codeql_selection_shape
        _codeql_suite_bytes
        _fuzz_execution_contract
        _fuzz_profile_preflight
        _gitleaks_coverage_preflight
        _gitleaks_disable_rule
        _gitleaks_mutation_valid
        _gitleaks_rule_ids
        _gitleaks_rule_inventory
        _json_size_upper_bound
        _json_string_size
        _json_value_size
        _native_argv
        _native_budget_error
        _native_profile
        _native_profile_challenges
        _native_version
        _osv_config_rule_ids
        _osv_expected_policy
        _osv_mutation_valid
        _osv_policy_inputs
        _osv_profile_preflight
        _runtime_disable_rule
        _runtime_mutation_valid
        _runtime_rule_ids
        _runtime_rule_inventory
        _runtime_ruleset_preflight
        _semgrep_disable_rule
        _semgrep_mutation_file
        _semgrep_mutation_valid
        _semgrep_rule_ids
        _semgrep_rule_sources
        _semgrep_scanned_sources
        _toml_parser
        _trivy_expected_ids
        _trivy_ignore_ids
        _trivy_json_argv
        _trivy_matrix_ids
        _trivy_mutation
        _trivy_mutation_valid
        _trivy_policy_inputs
        _trivy_rule_id_valid
        execute_adapter_profile
        resolve_codeql_query_inventory
        verify_codeql_query_isolation
        verify_codeql_query_selection
        """.split()
    ),
    "sarif": frozenset(
        """
        _ZAP_TRACE_BOOTSTRAP
        _challenge_source_uri
        _codeql_parse_rows
        _codeql_result_path
        _codeql_result_sets
        _codeql_source_query
        _indexed_artifact_uri
        _junit_bytes
        _junit_case
        _junit_observations
        _junit_suite_counts
        _native_artifact_path
        _native_artifact_uri
        _native_coverage_counts
        _native_coverage_report
        _native_dependency_paths
        _native_junit
        _native_profile_report
        _native_report
        _native_sarif_metadata
        _native_sarif_paths
        _native_source_counts
        _native_source_path
        _normalize_challenge_artifact_paths
        _normalize_challenge_bases
        _normalize_challenge_invocation
        _normalize_challenge_message_paths
        _normalize_challenge_run
        _normalize_challenge_sarif_paths
        _osv_challenge_source_paths
        _osv_lookup_paths
        _osv_normalize_lookup_path
        _osv_normalize_result_source
        _osv_suppression_bytes
        _parse_runtime_junit
        _runtime_exit_consistency
        _runtime_report_file
        _semgrep_json_findings
        _semgrep_sarif_findings
        _trivy_bind_report_targets
        _trivy_check_statuses
        _trivy_clean_hcl_comments
        _trivy_closed_argv
        _trivy_decode_source_bytes
        _trivy_expected_failures
        _trivy_full_source_execution
        _trivy_hcl_block
        _trivy_hcl_char
        _trivy_hcl_line_depth
        _trivy_hcl_string_char
        _trivy_local_module_members
        _trivy_match_failure_rows
        _trivy_module_sources
        _trivy_native_checks
        _trivy_native_failure_rows
        _trivy_normalized_sarif
        _trivy_observation
        _trivy_observation_bytes
        _trivy_pair_facts
        _trivy_pair_identity
        _trivy_paired_runner
        _trivy_parse_module_blocks
        _trivy_read_raw
        _trivy_root_module_graph
        _trivy_root_module_graphs
        _trivy_root_target_prefix
        _trivy_sarif_failures
        _trivy_source_bytes
        _trivy_source_map
        _trivy_target_bindings
        _trivy_target_members
        _trivy_target_name
        _trivy_terraform_file_target_members
        _trivy_validate_target_coverage
        _under_challenge_root
        _zap_trace_document
        _zap_trace_observations
        _zap_trace_routes
        _zap_trace_sources
        zap_source_trace_bootstrap
        zap_validate_source_trace
        """.split()
    ),
    "attestation": frozenset(
        """
        _atheris_challenge_retained_budget
        _attach_gitleaks_ledger
        _codeql_archived_sources
        _codeql_blob_bytes
        _codeql_native_blob
        _codeql_query_execution
        _codeql_query_result_record
        _codeql_retained_archive
        _codeql_retained_inventory
        _codeql_retained_invocation
        _codeql_source_accounting
        _codeql_source_measurement
        _codeql_source_state
        _codeql_steps_facts
        _codeql_verify_retained_query
        _codeql_verify_retained_source
        _fuzz_replay_control_evidence
        _fuzz_retained_bundle_shape
        _fuzz_retained_control_evidence
        _fuzz_retained_control_kinds
        _fuzz_retained_execution_artifacts
        _fuzz_retained_expected
        _fuzz_retained_gaps
        _fuzz_retained_obligation_valid
        _fuzz_retained_observations
        _gitleaks_accounting
        _gitleaks_accounting_complete
        _gitleaks_counter_values
        _gitleaks_coverage_errors
        _gitleaks_disposition
        _gitleaks_ledger_binding
        _gitleaks_ledger_identity
        _gitleaks_ledger_matrix
        _gitleaks_ledger_rows
        _gitleaks_ledger_shape
        _gitleaks_ledger_status
        _gitleaks_preflight
        _gitleaks_row_values
        _gitleaks_scanned_bytes
        _gitleaks_source_map
        _gitleaks_stderr_path
        _ledger_metadata_matches
        _native_profile_coverage
        _native_runtime_accounting
        _native_source_accounting
        _osv_challenge_retained_budget
        _osv_database_artifact
        _osv_database_identity
        _osv_native_blob
        _osv_native_bytes
        _osv_normalize_retained_paths
        _osv_primary_evidence
        _osv_primary_retained
        _osv_retained_controls_match
        _osv_retained_expected
        _osv_retained_observations
        _osv_retained_observed
        _osv_source_root_prefix
        _read_gitleaks_ledger
        _retained_fuzz_corpus
        _runtime_coverage_errors
        _semgrep_evidence_inputs
        _semgrep_fixture_binding
        _semgrep_observation_identity
        _semgrep_raw_bindings
        _semgrep_rule_inventory
        _semgrep_rule_runs
        _semgrep_source_accounting
        _stable_ledger_read
        _trivy_challenge_evidence
        _trivy_coverage_errors
        _trivy_evidence_inputs
        verify_codeql_retained_evidence
        verify_fuzz_retained_evidence
        verify_osv_retained_challenge
        verify_osv_retained_evidence
        verify_semgrep_rule_execution
        verify_trivy_rule_execution
        """.split()
    ),
    "loop": frozenset(
        """
        _atheris_challenge_command
        _atheris_challenge_control
        _atheris_challenge_gaps
        _atheris_challenge_report
        _atheris_challenges
        _atheris_obligations
        _challenge_bundle
        _challenge_error_code
        _challenge_gap_record
        _codeql_challenge_case
        _codeql_challenge_inputs
        _codeql_challenge_report
        _codeql_challenge_selection
        _codeql_challenge_steps
        _codeql_challenges
        _codeql_mutation_suite
        _codeql_replay_decode
        _codeql_replay_fresh
        _codeql_replay_queries
        _codeql_replay_remaining
        _codeql_replay_selection
        _codeql_replay_source_values
        _codeql_replay_sources
        _codeql_replay_values
        _codeql_step_streams
        _codeql_steps_runner
        _codeql_telemetry_notification
        _execute_codeql_challenge
        _finalize_fuzz_report
        _fuzz_control_args
        _fuzz_control_ids
        _fuzz_corpus_document
        _fuzz_corpus_entry
        _fuzz_disable_rule
        _fuzz_fixture_manifest_binding
        _fuzz_record_input
        _fuzz_replay_controls
        _fuzz_replay_expected
        _fuzz_replay_harness
        _fuzz_replay_inputs_main
        _fuzz_replay_module
        _fuzz_replay_profile
        _fuzz_replay_remaining
        _fuzz_replayed_failure_inputs_valid
        _fuzz_snapshot
        _gitleaks_challenge_allowed
        _gitleaks_challenge_report
        _gitleaks_challenges
        _gitleaks_challenges_complete
        _gitleaks_obligations
        _is_digest
        _native_challenge_bindings
        _osv_challenge_artifacts_valid
        _osv_challenge_command
        _osv_challenge_control
        _osv_challenge_controls_match
        _osv_challenge_execution
        _osv_challenge_gaps
        _osv_challenge_manifest
        _osv_challenge_report_bytes
        _osv_challenge_runner
        _osv_challenges
        _osv_challenges_complete
        _osv_check_deadline
        _osv_execution_bindings
        _osv_mutation_path
        _osv_obligations
        _osv_parse_challenge_report
        _osv_replay_compare_controls
        _osv_replay_control_ids
        _osv_replay_controls
        _osv_replay_execution_facts
        _osv_replay_identities
        _osv_replay_primary
        _osv_replay_remaining
        _osv_replay_row_map
        _osv_replay_semantics_match
        _run_atheris_challenge
        _run_codeql_challenge
        _run_gitleaks_challenge
        _run_osv_challenge
        _run_semgrep_challenge
        _run_trivy_challenge
        _runtime_challenge
        _runtime_challenge_report
        _runtime_challenges
        _runtime_encoded_argv
        _runtime_has_sentinel
        _runtime_mutation_config
        _runtime_obligations
        _semgrep_challenge_command
        _semgrep_challenge_report
        _semgrep_challenge_result
        _semgrep_challenges
        _semgrep_obligations
        _trivy_challenge_command
        _trivy_challenge_control
        _trivy_challenge_report
        _trivy_challenges
        _trivy_effective_ids
        _trivy_mutation_path
        _trivy_obligations
        _validate_fuzz_corpus
        _validate_fuzz_corpus_inputs
        _validate_fuzz_replay_observation
        _validate_fuzz_replayed_control
        _validate_fuzz_replayed_controls
        execute_codeql_native_replay
        execute_fuzz_native_replay
        execute_osv_native_replay
        native_fuzz_main
        """.split()
    ),
    "deep_audit": frozenset(
        """
        _native_challenge_executor
        _native_zap_main
        _profile_adapter_main
        _run_native_profile
        _run_zap_native_scan
        _zap_api
        _zap_api_arguments
        _zap_check_daemon
        _zap_daemon_argv
        _zap_daemon_environment
        _zap_enabled_inventory
        _zap_file_signature
        _zap_measure_scan
        _zap_native_request
        _zap_native_v2_context
        _zap_probe_target
        _zap_process_facts
        _zap_retained_ledger
        _zap_select_rules
        _zap_start_scan
        _zap_target_base_url
        _zap_validate_target_watch
        _zap_wait_passive_scan
        _zap_wait_ready
        _zap_wait_scan
        _zap_watch
        adapter_main
        execute_native_profile
        """.split()
    ),
}


def __getattr__(name: str):
    for owner, exports in _MOVED_EXPORTS.items():
        if name in exports:
            module = importlib.import_module(
                f".{_MOVED_EXPORT_MODULES[owner]}", __package__
            )
            return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
