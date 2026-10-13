"""Read-only shared control plane for human review and connected agents.

This is intentionally separate from :mod:`factoryline.control_plane`, which is
the tenant-scoped evidence store.  It only summarizes hash-bound local facts;
it cannot approve, execute, repair, merge, publish, or access credentials.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json
import os
import stat
import tempfile
import time
import copy

from .lifecycle_ledger import lifecycle_projection
from .operations_control import operations_control_projection
from .oracle_firewall import oracle_firewall_projection
from .repair_loop import repair_loop_projection
from .runtime_audit import runtime_audit_status
from .deep_audit import deep_audit_status
from .protocol_enums import MissionControlState
from .release_integrity import release_integrity
from .supply_chain import supply_chain_status
from .context_efficiency import context_efficiency_status
from .intake_parameters import intake_parameters_status


SCHEMA = "factory.mission-control-status.v1"
SECURITY_SCAN_RECEIPT_PATH = ".factory/security-scan/latest.json"
SECURITY_SCAN_RECEIPT_SCHEMA = "factory.security-scan-receipt.v1"
SECURITY_SCAN_STATUS_SCHEMA = "factory.security-scan-status.v1"
MAX_SECURITY_SCAN_RECEIPT_BYTES = 10_000_000
MAX_SECURITY_SCAN_SOURCE_BYTES = 64 * 1024 * 1024
MAX_SECURITY_SCAN_DISPLAY_FINDINGS = 24
AUTHORITY = {
    "execution": False,
    "approval": False,
    "repair": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


def _release_workflow_integrity(root: Path) -> dict[str, Any]:
    """Read release topology only when the workspace declares a release workflow."""
    workflow = Path(root) / ".github" / "workflows" / "publish.yml"
    if not workflow.is_file():
        return {
            "schema": "factory.release_integrity.v1",
            "marker": "RELEASE_INTEGRITY_NOT_APPLICABLE",
            "applicable": False,
            "ok": True,
            "checks": [],
            "failed_check_ids": [],
            "claim_boundary": "No declared publish workflow exists in this workspace; no release topology was inferred.",
        }
    return {**release_integrity(root), "applicable": True}


def _collect_evidence(root: Path, spans: list | None = None) -> dict[str, Any]:
    readers = (
        ("oracle", oracle_firewall_projection),
        ("operations", operations_control_projection),
        ("lifecycle", lifecycle_projection),
        ("repair_loops", repair_loop_projection),
        ("runtime_assurance", runtime_audit_status),
        ("deep_audit", deep_audit_status),
        ("release_workflow_integrity", _release_workflow_integrity),
    )
    evidence = {}
    for name, reader in readers:
        started = time.perf_counter_ns()
        evidence[name] = reader(root)
        elapsed = time.perf_counter_ns() - started
        if spans is not None:
            spans.append(
                {
                    "name": name,
                    "elapsed_ns": elapsed,
                    "output_sha256": _fingerprint(evidence[name]),
                }
            )
    # Keep the established seven-reader profile stable for latency baselines;
    # this additional receipt is a read-only status projection, not a timed
    # gate and must not perturb existing profiling receipts.
    evidence["supply_chain"] = supply_chain_status(Path(root).resolve())
    # Bounded cache metadata only; keep it outside the seven-reader timing
    # baseline so the established performance receipt remains comparable.
    evidence["context_efficiency"] = context_efficiency_status(Path(root).resolve())
    # Keep the established seven-reader timing baseline stable; this envelope
    # is an additional bounded, read-only projection.
    evidence["intake_parameters"] = intake_parameters_status(Path(root).resolve())
    # This receipt reader is intentionally outside the existing timing sample.
    evidence["implementation_audit"] = security_scan_status(Path(root).resolve())
    return evidence


def _fingerprint(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _security_scan_hash(value: Any, *, ensure_ascii: bool) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=ensure_ascii,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _security_scan_add_binding(
    rows: dict[str, dict[str, Any]], row: Any, role: str
) -> None:
    if not isinstance(row, dict):
        raise ValueError("security scan source binding is malformed")
    path, sha256, size = row.get("path"), row.get("sha256"), row.get("bytes")
    if (
        not isinstance(path, str)
        or not isinstance(sha256, str)
        or len(sha256) != 64
        or any(char not in "0123456789abcdef" for char in sha256)
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
    ):
        raise ValueError("security scan source binding is malformed")
    value = {"path": path, "sha256": sha256, "bytes": size, "role": role}
    if path in rows:
        if rows[path] != value:
            raise ValueError("security scan source paths are duplicated")
        return
    rows[path] = value


def _security_scan_source_bindings(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}

    sources = report.get("sources")
    oracle = report.get("oracle_context")
    if not isinstance(sources, list) or not isinstance(oracle, dict):
        raise ValueError("security scan source manifest is malformed")
    for row in sources:
        _security_scan_add_binding(rows, row, "source")
    configs = oracle.get("configuration_sources", [])
    if not isinstance(configs, list):
        raise ValueError("security scan configuration manifest is malformed")
    for row in configs:
        _security_scan_add_binding(rows, row, "configuration")
    tenant = report.get("tenant_read_contract")
    configuration = tenant.get("configuration") if isinstance(tenant, dict) else None
    if isinstance(configuration, dict) and configuration.get("state") == "loaded":
        _security_scan_add_binding(rows, configuration, "tenant_configuration")
    return sorted(rows.values(), key=lambda row: (row["path"], row["role"]))


def _security_scan_report_error(report: Any) -> str | None:
    if (
        not isinstance(report, dict)
        or report.get("schema") != "factory.security-audit.v1"
    ):
        return "report_schema_invalid"
    if report.get("marker") != "SECURITY_AUDIT_COMPLETE":
        return "report_marker_invalid"
    for field, payload, ensure_ascii in (
        (
            "candidate_sha256",
            {
                key: report.get(key, {})
                for key in ("sources", "tenant_read_contract", "oracle_context")
            },
            True,
        ),
        (
            "source_manifest_sha256",
            {key: report.get(key, {}) for key in ("sources", "oracle_context")},
            False,
        ),
        (
            "audit_sha256",
            {key: value for key, value in report.items() if key != "audit_sha256"},
            False,
        ),
    ):
        claimed = report.get(field)
        if (
            not isinstance(claimed, str)
            or len(claimed) != 64
            or any(char not in "0123456789abcdef" for char in claimed)
            or _security_scan_hash(payload, ensure_ascii=ensure_ascii) != claimed
        ):
            return f"{field}_mismatch"
    return None


def security_scan_pytest_collection_snapshot(root: Path) -> dict[str, Any]:
    """Capture effective pytest collection settings without executing project code."""
    from .review_audits import _pytest_collection_config

    patterns, identity = _pytest_collection_config(Path(root).resolve())
    return {**identity, "patterns": sorted(patterns)}


def prepare_security_scan_receipt_report(
    root: Path, report: dict[str, Any], before_collection: dict[str, Any]
) -> dict[str, Any]:
    """Bind pre/post scan pytest config observations before writing a local receipt."""
    from .review_audits import _seal_security_scan

    prepared = copy.deepcopy(report)
    after = security_scan_pytest_collection_snapshot(root)
    stable = before_collection == after
    collection = {
        **after,
        "capture_state": "stable_pre_post" if stable else "changed_during_scan",
    }
    oracle = prepared.get("oracle_context")
    if not isinstance(oracle, dict):
        raise ValueError("security scan oracle context is malformed")
    oracle["pytest_collection"] = collection
    configs = oracle.get("configuration_sources")
    if not isinstance(configs, list):
        raise ValueError("security scan configuration manifest is malformed")
    if isinstance(after.get("path"), str):
        row = {
            "path": after["path"],
            "sha256": after.get("sha256"),
            "bytes": after.get("bytes"),
        }
        if row not in configs:
            configs.append(row)
            configs.sort(key=lambda item: item.get("path", ""))
    if not stable:
        prepared["state"] = "INCOMPLETE"
        prepared["action_summary"] = (
            str(prepared.get("action_summary", ""))
            + " Pytest collection configuration changed during the scan; rerun before relying on coverage."
        ).strip()
    prepared["source_manifest_sha256"] = _security_scan_hash(
        {"sources": prepared.get("sources", []), "oracle_context": oracle},
        ensure_ascii=False,
    )
    return _seal_security_scan(prepared)


def _security_scan_receipt_directory(root: Path, *, create: bool) -> Path:
    workspace = Path(root).resolve()
    directory = workspace
    for part in (".factory", "security-scan"):
        directory = directory / part
        try:
            info = directory.lstat()
        except FileNotFoundError:
            if not create:
                raise
            directory.mkdir()
            info = directory.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("security scan receipt directory is linked")
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("security scan receipt parent is not a directory")
    return directory


def write_security_scan_receipt(root: Path, report: dict[str, Any]) -> dict[str, str]:
    """Atomically store one explicit CLI scan report as unsigned local evidence."""
    from .deep_audit_io import canonical_bytes, local_file

    error = _security_scan_report_error(report)
    if error is not None:
        raise ValueError(f"security scan report is not sealed: {error}")
    source_bindings = _security_scan_source_bindings(report)
    envelope = {
        "schema": SECURITY_SCAN_RECEIPT_SCHEMA,
        "report": report,
        "source_bindings": source_bindings,
    }
    envelope["receipt_sha256"] = _security_scan_hash(envelope, ensure_ascii=False)
    raw = canonical_bytes(envelope)
    if len(raw) > MAX_SECURITY_SCAN_RECEIPT_BYTES:
        raise ValueError("security scan receipt exceeds its size limit")
    directory = _security_scan_receipt_directory(root, create=True)
    path = directory / "latest.json"
    try:
        local_file(Path(root).resolve(), SECURITY_SCAN_RECEIPT_PATH)
    except Exception as exc:
        from .deep_audit_io import RuntimeAuditError

        if not isinstance(exc, RuntimeAuditError) or exc.code != "E_SOURCE_MISSING":
            raise ValueError(
                "existing security scan receipt is not a regular file"
            ) from exc
    descriptor, temporary = tempfile.mkstemp(
        prefix=".latest.", suffix=".tmp", dir=directory
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return {
        "path": SECURITY_SCAN_RECEIPT_PATH,
        "receipt_sha256": envelope["receipt_sha256"],
    }


def _security_scan_unknown(
    state: str, reason: str, *, output_truncated: bool = False
) -> dict[str, Any]:
    return {
        "schema": SECURITY_SCAN_STATUS_SCHEMA,
        "state": state,
        "report_state": None,
        "reason": reason,
        "receipt_path": SECURITY_SCAN_RECEIPT_PATH,
        "receipt_sha256": None,
        "candidate_sha256": None,
        "source_manifest_sha256": None,
        "candidate_freshness": "NOT_ESTABLISHED",
        "source_count": None,
        "finding_count": None,
        "finding_counts": {},
        "findings": [],
        "findings_truncated": False,
        "display_truncated": False,
        "output_truncated": output_truncated,
        "incomplete": state in {"INCOMPLETE", "INVALID"},
        "audit_coverage": {"complete": False, "measurement_state": state.lower()},
        "verification": "local_self_hash_only_not_signature_or_approval",
        "authority": {"execution": False, "approval": False, "repair": False},
        "claim_boundary": "No current complete static security scan receipt is available; this is not a release or security approval.",
    }


def _security_scan_read_receipt(root: Path) -> tuple[dict[str, Any] | None, bool]:
    from .deep_audit_io import RuntimeAuditError, local_file, strict_json

    try:
        path = local_file(root, SECURITY_SCAN_RECEIPT_PATH)
    except RuntimeAuditError as exc:
        if exc.code == "E_SOURCE_MISSING":
            return None, False
        raise
    with path.open("rb") as stream:
        before = path.stat()
        raw = stream.read(MAX_SECURITY_SCAN_RECEIPT_BYTES + 1)
        after = path.stat()
    if len(raw) > MAX_SECURITY_SCAN_RECEIPT_BYTES:
        return None, True
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ValueError("security scan receipt changed during read")
    return strict_json(raw), False


def _security_scan_coverage(report: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    coverage = report.get("audit_coverage")
    if not isinstance(coverage, dict):
        raise ValueError("security scan coverage is malformed")
    numeric = ("files_discovered", "files_attempted", "files_audited")
    if any(
        isinstance(coverage.get(key), bool)
        or not isinstance(coverage.get(key), int)
        or coverage[key] < 0
        for key in numeric
    ):
        raise ValueError("security scan coverage counts are malformed")
    complete = (
        coverage.get("complete") is True
        and coverage.get("inventory_complete") is True
        and coverage.get("measurement_state") == "complete"
        and coverage["files_discovered"] == coverage["files_attempted"]
        and coverage["files_attempted"] == coverage["files_audited"]
        and coverage["files_audited"] == report.get("files_scanned")
        and coverage["files_discovered"] > 0
    )
    return {
        "language": coverage.get("language"),
        "files_discovered": coverage["files_discovered"],
        "files_attempted": coverage["files_attempted"],
        "files_audited": coverage["files_audited"],
        "measurement_state": coverage.get("measurement_state"),
        "complete": complete,
        "limit": coverage.get("limit"),
    }, complete


def _security_scan_verify_one_binding(
    root: Path, row: dict[str, Any], total: int
) -> tuple[str | None, int]:
    from .deep_audit_io import RuntimeAuditError, local_file
    from .review_audits import MAX_BYTES

    try:
        path = local_file(root, row["path"])
    except RuntimeAuditError as exc:
        if exc.code == "E_SOURCE_MISSING":
            return "SOURCE_MISSING", total
        raise
    limit = MAX_BYTES
    if path.stat().st_size > limit:
        return "SOURCE_SIZE_LIMIT", total
    with path.open("rb") as stream:
        before = path.stat()
        raw = stream.read(limit + 1)
        after = path.stat()
    total += len(raw)
    if total > MAX_SECURITY_SCAN_SOURCE_BYTES:
        return "SOURCE_VERIFICATION_BUDGET", total
    if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
        return "SOURCE_HASH_MISMATCH", total
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        return "SOURCE_CHANGED_DURING_READ", total
    return None, total


def _security_scan_verify_source_bindings(
    root: Path, bindings: list[dict[str, Any]]
) -> str | None:
    total = 0
    for row in bindings:
        error, total = _security_scan_verify_one_binding(root, row, total)
        if error is not None:
            return error
    return None


def _security_scan_current_sources(
    root: Path, report: dict[str, Any], bindings: list[dict[str, Any]]
) -> str:
    from .review_audits import MAX_SECURITY_SOURCE_FILES, _security_source_files

    current_paths = _security_source_files(root)
    if len(current_paths) > MAX_SECURITY_SOURCE_FILES:
        return "SOURCE_INVENTORY_OVER_LIMIT"
    expected = {row["path"] for row in bindings if row["role"] == "source"}
    current = {path.relative_to(root).as_posix() for path in current_paths}
    coverage, complete = _security_scan_coverage(report)
    if complete and expected != current:
        return "SOURCE_INVENTORY_MISMATCH"
    error = _security_scan_verify_source_bindings(root, bindings)
    if error is not None:
        return error
    collection = _security_scan_pytest_collection(root, report, bindings)
    if collection != "CURRENT_PYTEST_COLLECTION_VERIFIED":
        return collection
    return "CURRENT_SOURCE_HASHES_VERIFIED"


def _security_scan_pytest_collection(
    root: Path, report: dict[str, Any], bindings: list[dict[str, Any]]
) -> str:
    """Recheck the selected pytest config without importing or executing project code."""
    oracle = report.get("oracle_context")
    identity = oracle.get("pytest_collection") if isinstance(oracle, dict) else None
    if not isinstance(identity, dict):
        return "PYTEST_COLLECTION_NOT_BOUND"
    patterns = identity.get("patterns")
    if not isinstance(patterns, list) or any(
        not isinstance(item, str) for item in patterns
    ):
        return "PYTEST_COLLECTION_BINDING_INVALID"
    if identity.get("capture_state") != "stable_pre_post":
        return "PYTEST_COLLECTION_CHANGED_DURING_SCAN"
    try:
        from .review_audits import ReviewAuditError, _pytest_collection_config

        current_patterns, current_identity = _pytest_collection_config(root)
    except Exception as exc:
        from .review_audits import ReviewAuditError

        if isinstance(exc, ReviewAuditError):
            return "PYTEST_COLLECTION_CONFIG_UNAVAILABLE"
        raise
    sealed = {
        key: value
        for key, value in identity.items()
        if key not in {"patterns", "capture_state"}
    }
    if sealed != current_identity or patterns != sorted(current_patterns):
        return "PYTEST_COLLECTION_CONFIG_CHANGED"
    selected_path = identity.get("path")
    if selected_path is not None:
        selected = [
            row
            for row in bindings
            if row["role"] == "configuration" and row["path"] == selected_path
        ]
        if not selected or any(
            row.get("sha256") != identity.get("sha256")
            or row.get("bytes") != identity.get("bytes")
            for row in selected
        ):
            return "PYTEST_COLLECTION_SOURCE_NOT_BOUND"
    return "CURRENT_PYTEST_COLLECTION_VERIFIED"


def _security_probe_projection(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result = {
        key: value[key]
        for key in (
            "available",
            "call_available",
            "exact_collection_id_required",
        )
        if type(value.get(key)) is bool
    }
    for key in ("assertion_lines", "call_lines"):
        rows = value.get(key)
        if isinstance(rows, list):
            result[key] = [item for item in rows[:32] if type(item) is int and item > 0]
    for key in ("command", "call_command", "call_limits"):
        rows = value.get(key)
        if isinstance(rows, list):
            result[key] = [item[:200] for item in rows[:16] if isinstance(item, str)]
    for key in ("nodeid_hint", "execution", "interpretation"):
        item = value.get(key)
        if isinstance(item, str):
            result[key] = item[:500]
    return result or None


def _security_finding_projection(finding: Any) -> dict[str, Any]:
    if not isinstance(finding, dict):
        raise ValueError("security scan finding is malformed")
    row = {}
    facts = finding.get("facts", {})
    if not isinstance(facts, dict):
        facts = {}
    for key in ("code", "severity", "path", "symbol", "message"):
        value = finding.get(key)
        if value is None:
            value = facts.get(key)
        if isinstance(value, str):
            row[key] = value[:800]
    line = finding.get("line")
    if type(line) is int and line > 0:
        row["line"] = line
    probe = _security_probe_projection(
        finding.get("native_assertion_probe", facts.get("native_assertion_probe"))
    )
    if probe is not None:
        row["native_assertion_probe"] = probe
    return row


def _security_finding_counts(report: dict[str, Any]) -> dict[str, int]:
    counts = report.get("finding_counts")
    if not isinstance(counts, dict) or any(
        not isinstance(code, str)
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        for code, count in counts.items()
    ):
        raise ValueError("security scan finding counts are malformed")
    return dict(sorted(counts.items())[:64])


def _security_findings_projection(
    report: dict[str, Any],
) -> tuple[list[dict[str, Any]], bool, dict[str, int]]:
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("security scan findings are malformed")
    result = [
        _security_finding_projection(finding)
        for finding in findings[:MAX_SECURITY_SCAN_DISPLAY_FINDINGS]
    ]
    counts = _security_finding_counts(report)
    return result, len(findings) > len(result), counts


def _security_scan_projection(
    report: dict[str, Any], receipt_sha256: str, freshness: str
) -> dict[str, Any]:
    coverage, coverage_complete = _security_scan_coverage(report)
    findings, display_truncated, counts = _security_findings_projection(report)
    tenant = report.get("tenant_read_contract", {})
    configuration = tenant.get("configuration", {}) if isinstance(tenant, dict) else {}
    tenant_config_state = (
        configuration.get("state", "missing")
        if isinstance(configuration, dict)
        else "invalid"
    )
    report_state = report.get("state")
    state = report_state
    incomplete = (
        not coverage_complete
        or freshness != "CURRENT_SOURCE_HASHES_VERIFIED"
        or tenant_config_state != "loaded"
        or report_state in {"INCOMPLETE", "NO_SOURCES"}
        or report.get("output_truncated") is True
    )
    if incomplete:
        state = "INCOMPLETE"
    return {
        "schema": SECURITY_SCAN_STATUS_SCHEMA,
        "state": state,
        "report_state": report_state,
        "reason": freshness if freshness != "CURRENT_SOURCE_HASHES_VERIFIED" else None,
        "receipt_path": SECURITY_SCAN_RECEIPT_PATH,
        "receipt_sha256": receipt_sha256,
        "candidate_sha256": report.get("candidate_sha256"),
        "source_manifest_sha256": report.get("source_manifest_sha256"),
        "candidate_freshness": freshness,
        "source_count": coverage["files_audited"],
        "finding_count": len(report["findings"]),
        "finding_counts": counts,
        "findings": findings,
        "findings_truncated": display_truncated,
        "display_truncated": display_truncated,
        "output_truncated": report.get("output_truncated") is True,
        "incomplete": state == "INCOMPLETE",
        "audit_coverage": coverage,
        "tenant_read_configuration": tenant_config_state,
        "verification": "local_self_hash_only_not_signature_or_approval",
        "authority": {"execution": False, "approval": False, "repair": False},
        "claim_boundary": "Current local source hashes and self-hashes were checked. This unsigned AST report is advisory; it does not establish trust, semantic correctness, or release approval.",
    }


def _security_scan_finding_counts_error(report: dict[str, Any]) -> str | None:
    _security_findings_projection(report)
    actual_counts: dict[str, int] = {}
    for finding in report["findings"]:
        facts = finding.get("facts", {}) if isinstance(finding, dict) else {}
        code = finding.get("code") if isinstance(finding, dict) else None
        if code is None and isinstance(facts, dict):
            code = facts.get("code")
        if not isinstance(code, str) or not code:
            return "finding code is missing"
        actual_counts[code] = actual_counts.get(code, 0) + 1
    if report.get("finding_counts") != dict(sorted(actual_counts.items())):
        return "finding count mismatch"
    return None


def _security_scan_report_consistency_error(
    report: dict[str, Any], source_bindings: list[dict[str, Any]]
) -> str | None:
    error = _security_scan_finding_counts_error(report)
    if error is not None:
        return error
    if report.get("state") not in {
        "CLEAN",
        "FINDINGS",
        "BLOCKED",
        "INCOMPLETE",
        "NO_SOURCES",
    }:
        return "scan state is invalid"
    if report.get("state") == "CLEAN" and report["findings"]:
        return "clean scan contains findings"
    coverage, coverage_complete = _security_scan_coverage(report)
    source_count = sum(row["role"] == "source" for row in source_bindings)
    if coverage_complete and coverage["files_audited"] != source_count:
        return "source count does not match coverage"
    return None


def _security_scan_receipt_report(
    envelope: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]] | None, str | None]:
    from .deep_audit_io import digest

    if set(envelope) != {"schema", "report", "source_bindings", "receipt_sha256"}:
        return None, None, "receipt fields are invalid"
    claimed = envelope.get("receipt_sha256")
    unsigned = {
        key: value for key, value in envelope.items() if key != "receipt_sha256"
    }
    if envelope.get("schema") != SECURITY_SCAN_RECEIPT_SCHEMA or claimed != digest(
        unsigned
    ):
        return None, None, "receipt digest or schema mismatch"
    report = envelope.get("report")
    error = _security_scan_report_error(report)
    if error is not None:
        return None, None, error
    source_bindings = _security_scan_source_bindings(report)
    if envelope.get("source_bindings") != source_bindings:
        return None, None, "source manifest mismatch"
    error = _security_scan_report_consistency_error(report, source_bindings)
    if error is not None:
        return None, None, error
    return report, source_bindings, None


def _security_scan_read_error(exc: Exception) -> dict[str, Any]:
    from .deep_audit_io import RuntimeAuditError

    if isinstance(exc, RuntimeAuditError) and exc.code == "E_SOURCE_MISSING":
        return _security_scan_unknown("NOT_RUN", "no receipt found")
    return _security_scan_unknown("INVALID", "receipt could not be verified")


def security_scan_status(root: Path) -> dict[str, Any]:
    """Read and verify the latest bounded local scanner receipt without running a scan."""
    workspace = Path(root).resolve()
    try:
        envelope, truncated = _security_scan_read_receipt(workspace)
        if truncated:
            return _security_scan_unknown(
                "INCOMPLETE", "receipt exceeds read limit", output_truncated=True
            )
        if envelope is None:
            return _security_scan_unknown("NOT_RUN", "no receipt found")
        claimed = envelope.get("receipt_sha256")
        report, source_bindings, error = _security_scan_receipt_report(envelope)
        if error is not None:
            return _security_scan_unknown("INVALID", error)
        assert report is not None and source_bindings is not None
        freshness = _security_scan_current_sources(workspace, report, source_bindings)
        return _security_scan_projection(report, claimed, freshness)
    except Exception as exc:
        return _security_scan_read_error(exc)


def mission_control_profile(root: Path) -> dict[str, Any]:
    """Measure local evidence readers without exporting their bodies or authorizing any action."""
    spans: list[dict[str, Any]] = []
    _collect_evidence(Path(root).resolve(), spans)
    identities = [
        {"name": span["name"], "output_sha256": span["output_sha256"]} for span in spans
    ]
    return {
        "schema": "factory.mission-control-profile.v1",
        "spans": spans,
        "reader_elapsed_ns": sum(span["elapsed_ns"] for span in spans),
        "evidence_sha256": _fingerprint(identities),
        "authority": dict(AUTHORITY),
        "claim_boundary": "Local reader timings only; not an atomic filesystem snapshot, approval, signature or end-to-end speedup.",
    }


def mission_control_status(root: Path) -> dict[str, Any]:
    """Summarize local evidence gates without creating a hidden control path."""
    workspace = Path(root).resolve()
    evidence = _collect_evidence(workspace)
    blockers = _mission_control_blockers(evidence)
    blocked = any(blockers.values())
    human_required = _human_review_required(evidence, blocked)
    state = _mission_control_state(blocked, human_required)
    intake_state = evidence["intake_parameters"].get("state")
    return {
        "schema": SCHEMA,
        "marker": "MISSION_CONTROL_READ_ONLY",
        "state": state,
        "human_control_plane": _human_control_plane(
            state, human_required, blockers, intake_state, blocked
        ),
        "agent_control_plane": _agent_control_plane(),
        "blockers": blockers,
        "evidence": evidence,
        "authority": dict(AUTHORITY),
        "claim_boundary": (
            "This is a read-only coordination view. It does not create approval, execute an agent, "
            "repair code, alter Git, or perform any provider action."
        ),
    }


def _mission_control_blockers(evidence: dict[str, Any]) -> dict[str, int]:
    oracle = evidence["oracle"]
    operations = evidence["operations"]
    lifecycle = evidence["lifecycle"]
    repairs = evidence["repair_loops"]
    runtime = evidence["runtime_assurance"]
    release_workflow = evidence["release_workflow_integrity"]
    supply_chain = evidence["supply_chain"]
    context_efficiency = evidence["context_efficiency"]
    intake_parameters = evidence["intake_parameters"]
    blockers = {
        "oracle_invalid": int(oracle.get("invalid_count", 0)),
        "oracle_weakening": int(oracle.get("blocked_drift_count", 0)),
        "operations_blocked": int(operations.get("blocked_count", 0)),
        "operations_invalid": int(operations.get("invalid_count", 0)),
        "lifecycle_invalid": int(lifecycle.get("invalid_count", 0)),
        "repair_invalid": int(repairs.get("invalid_count", 0)),
        "runtime_assurance_blocked": int(
            runtime.get("state") in {"BLOCKED", "INCOMPLETE"}
        ),
        "deep_audit_blocked": int(
            evidence["deep_audit"].get("state") in {"BLOCKED", "INCOMPLETE"}
        ),
        "release_workflow_blocked": int(
            release_workflow.get("applicable") is True
            and release_workflow.get("ok") is not True
        ),
        "supply_chain_blocked": int(
            supply_chain.get("state") in {"BLOCKED", "INCOMPLETE"}
        ),
        "context_efficiency_blocked": int(context_efficiency.get("state") == "BLOCKED"),
        "intake_parameters_blocked": int(intake_parameters.get("state") == "BLOCKED"),
        "intake_parameters_review_required": int(
            intake_parameters.get("state") == "REVIEW_REQUIRED"
        ),
    }
    return blockers


def _human_review_required(evidence: dict[str, Any], blocked: bool) -> bool:
    lifecycle = evidence["lifecycle"]
    repairs = evidence["repair_loops"]
    intake_parameters = evidence["intake_parameters"]
    return (
        blocked
        or evidence["deep_audit"].get("state") == "READY_FOR_HUMAN_REVIEW"
        or evidence["runtime_assurance"].get("state") == "READY_FOR_HUMAN_REVIEW"
        or int(lifecycle.get("review_required_count", 0)) > 0
        or int(repairs.get("receipt_count", 0)) > 0
        or intake_parameters.get("state") == "REVIEW_REQUIRED"
    )


def _mission_control_state(blocked: bool, human_required: bool) -> str:
    return (
        MissionControlState.BLOCKED.value
        if blocked
        else MissionControlState.REVIEW_REQUIRED.value
        if human_required
        else MissionControlState.EVIDENCE_MISSING.value
    )


def _human_control_plane(
    state: str,
    human_required: bool,
    blockers: dict[str, int],
    intake_state: Any,
    blocked: bool,
) -> dict[str, Any]:
    return {
        "state": state,
        "review_required": human_required,
        "can_approve_here": False,
        "next_action": _human_next_action(
            blockers, intake_state, blocked, human_required
        ),
    }


def _human_next_action(
    blockers: dict[str, int],
    intake_state: Any,
    blocked: bool,
    human_required: bool,
) -> str:
    if blockers["release_workflow_blocked"]:
        return "repair_release_workflow"
    if blockers["supply_chain_blocked"]:
        return "repair_supply_chain_attestation"
    if blockers["context_efficiency_blocked"]:
        return "repair_context_efficiency_packet"
    if blockers["intake_parameters_blocked"]:
        return "repair_intake_parameters"
    if intake_state == "REVIEW_REQUIRED":
        return "review_intake_parameters"
    if blocked:
        return "repair_evidence_chain"
    if human_required:
        return "named_human_review"
    return "seal_intent_and_collect_local_evidence"


def _agent_control_plane() -> dict[str, Any]:
    return {
        "state": MissionControlState.SUPERVISED_ONLY.value,
        "may_read": [
            "sealed_oracle_contract",
            "operations_receipt",
            "session_trace",
            "repair_loop_packet",
            "runtime_assurance_receipt",
            "deep_audit_receipt",
            "security_scan_receipt",
            "release_workflow_integrity",
            "supply_chain_receipt",
            "context_efficiency_packet",
            "intake_parameters_envelope",
        ],
        "may_not": [
            "alter_intent",
            "weaken_threshold",
            "authorize_repair",
            "merge",
            "publish",
            "deploy",
            "access_credentials",
        ],
        "handoff_rule": (
            "A connected agent must present local hash-bound facts; missing or changed facts "
            "return to named human review."
        ),
    }
