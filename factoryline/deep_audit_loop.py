"""Read-only repair comparisons and graph lineage; attestations grant no authority."""

from __future__ import annotations

from . import deep_audit_io as _deep_audit_io
from datetime import datetime, timezone
from dataclasses import dataclass, field
from hashlib import sha256
from io import BytesIO
from itertools import islice
from os import fstat
from pathlib import Path
from typing import Any
import re
import stat
from xml.etree import ElementTree

from .deep_audit import _read_receipt
from .deep_audit_attestation import (
    DeepAuditAttestationError,
    verify_deep_audit_attestation,
)
from .deep_audit_io import digest
from .runtime_audit_common import RuntimeAuditError


def _hash(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("missing or invalid digest")
    return value


def _load(root: Path, relative: str) -> dict:
    receipt, sha, _ = _read_receipt(root, root / relative)
    for key in (
        "ruleset_sha256",
        "canary_set_sha256",
        "candidate_sha256",
        "plan_sha256",
    ):
        _hash(receipt[key])
    for key in ("report_hashes", "canary_hashes"):
        values = receipt[key]
        if not isinstance(values, dict) or not 1 <= len(values) <= 8:
            raise ValueError("missing analyzer coverage")
        for value in values.values():
            _hash(value)
    if set(receipt["report_hashes"]) != set(receipt["canary_hashes"]):
        raise ValueError("canary coverage differs")
    _validate_findings(receipt)
    return {**receipt, "receipt_sha256": sha}


def _validate_findings(receipt: dict) -> None:
    for key in ("findings", "repair_queue"):
        if not isinstance(receipt[key], list) or len(receipt[key]) > 20_000:
            raise ValueError("invalid evidence collection")
    identities = [_hash(item["finding_id"]) for item in receipt["findings"]]
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate finding identity")
    for item in receipt["repair_queue"]:
        if not isinstance(item, dict) or not isinstance(item.get("code"), str):
            raise ValueError("invalid repair action")


def _action_ids(receipt: dict) -> set:
    return {
        digest(
            {
                key: item.get(key)
                for key in ("code", "finding_id", "rule_id", "canary_id", "analyzer_id")
            }
        )
        for item in receipt["repair_queue"]
    }


def _compare(before: dict, after: dict) -> dict:
    for key in ("ruleset_sha256", "canary_set_sha256"):
        if before[key] != after[key]:
            raise RuntimeAuditError(
                "E_DEEP_POLICY_CHANGED",
                "Policy or canary set changed; request independent review.",
            )
    if set(before["report_hashes"]) != set(after["report_hashes"]):
        raise RuntimeAuditError(
            "E_DEEP_COVERAGE_CHANGED",
            "Analyzer coverage changed; comparison cannot justify progress.",
        )
    old = {item["finding_id"] for item in before["findings"]}
    new = {item["finding_id"] for item in after["findings"]}
    introduced, resolved = sorted(new - old), sorted(old - new)
    new_actions = sorted(_action_ids(after) - _action_ids(before))
    if introduced or new_actions:
        state = "regressed"
    elif after["decision"] == "READY_FOR_HUMAN_REVIEW" and not after["repair_queue"]:
        state = "approval_required"
    elif resolved:
        state = "repair_required"
    else:
        state = "stagnated"
    return {
        "state": state,
        "introduced": introduced,
        "resolved": resolved,
        "new_blocker_ids": new_actions,
        "remaining_findings": len(new),
        "repair_queue": after["repair_queue"],
    }


def _attestation_summary(value: dict) -> dict:
    return {
        key: value[key]
        for key in (
            "attestation_sha256",
            "keyid",
            "identity",
            "issuer",
            "verifier",
            "freshness",
        )
    }


def _verify_compare_attestations(
    root: Path,
    before_path: str,
    after_path: str,
    before_attestation: str | None,
    after_attestation: str | None,
    trust_root_path: Path | None,
    require_attestation: bool,
    max_age_seconds: int,
    now: datetime | None,
    attestations: dict,
) -> None:
    """Validate pinned trust and retain each successfully verified attestation."""
    if (before_attestation or after_attestation) and trust_root_path is None:
        raise DeepAuditAttestationError(
            "E_DEEP_ATTESTATION_REQUIRED",
            "a pinned trust root is required for attestations",
        )
    if require_attestation and (
        not before_attestation or not after_attestation or trust_root_path is None
    ):
        raise DeepAuditAttestationError(
            "E_DEEP_ATTESTATION_REQUIRED",
            "strict comparison requires two attestations and a pinned trust root",
        )
    if before_attestation:
        attestations["before"] = verify_deep_audit_attestation(
            root,
            Path(before_attestation),
            Path(trust_root_path),
            Path(before_path),
            now=now,
            max_age_seconds=max_age_seconds,
        )
    if after_attestation:
        attestations["after"] = verify_deep_audit_attestation(
            root,
            Path(after_attestation),
            Path(trust_root_path),
            Path(after_path),
            now=now,
            max_age_seconds=max_age_seconds,
        )


def compare_deep_audits(
    root: Path,
    before_path: str,
    after_path: str,
    *,
    before_attestation: str | None = None,
    after_attestation: str | None = None,
    trust_root_path: Path | None = None,
    require_attestation: bool = False,
    max_age_seconds: int = 3600,
    now: datetime | None = None,
) -> dict:
    """Compare local receipts, optionally requiring independent fresh attestations; never repair or authorize."""
    root = Path(root).resolve()
    base = {
        "schema": "factory.deep-audit-comparison.v1",
        "authority": "none",
        "governance": "human_controlled",
        "verification": "self_hash_only_not_signature_or_freshness",
        "attestation_required": require_attestation,
        "attestations": {},
        "action_summary": "Compare findings and blockers; stop for human review on incompatibility, regression or no progress.",
    }
    attestations = {}
    try:
        _verify_compare_attestations(
            root,
            before_path,
            after_path,
            before_attestation,
            after_attestation,
            trust_root_path,
            require_attestation,
            max_age_seconds,
            now,
            attestations,
        )
        before, after = _load(root, before_path), _load(root, after_path)
        compared = _compare(before, after)
        return {
            **base,
            **compared,
            "before_sha256": before["receipt_sha256"],
            "after_sha256": after["receipt_sha256"],
            "attestations": {
                key: _attestation_summary(value) for key, value in attestations.items()
            },
            "verification": "offline_dsse_and_freshness"
            if attestations
            else base["verification"],
        }
    except (DeepAuditAttestationError, ValueError, OSError, KeyError, TypeError) as exc:
        return {
            **base,
            "state": "blocked",
            "code": getattr(exc, "code", "E_DEEP_RECEIPT_INVALID"),
            "attestations": {
                key: _attestation_summary(value) for key, value in attestations.items()
            },
        }


def deep_audit_lineage(root: Path, status: dict) -> dict:
    """Project at most fifty finding chains from the exact observed receipt, without trusting its signer."""
    base = {
        "state": status["state"],
        "chains": [],
        "truncated": False,
        "authority": "none",
    }
    if "receipt_path" not in status:
        return base
    try:
        root = Path(root).resolve()
        relative = Path(status["receipt_path"]).relative_to(root).as_posix()
        receipt = _load(root, relative)
        if receipt["receipt_sha256"] != status["receipt_sha256"]:
            raise ValueError("observation changed")
        chains = [_chain(item, receipt, relative) for item in receipt["findings"][:50]]
        return {
            **base,
            "receipt_path": relative,
            "receipt_sha256": receipt["receipt_sha256"],
            "chains": chains,
            "truncated": len(receipt["findings"]) > 50,
            "verification": "self_hash_only_not_signature_or_freshness",
        }
    except (ValueError, OSError, KeyError, TypeError, IndexError):
        return {**base, "state": "INCOMPLETE"}


def _chain(item: dict, receipt: dict, relative: str) -> dict:
    location = item["locations"][0]
    return {
        "finding_id": item["finding_id"],
        "source": location["path"],
        "source_sha256": location["source_sha256"],
        "obligation": item.get("obligation_id", "unmapped"),
        "trace_sha256": item["trace_sha256"],
        "receipt_path": relative,
        "decision": receipt["decision"],
        "handoff": "human_review_required",
    }


def _label(value: object, fallback: str) -> str:
    return value.strip()[:240] if isinstance(value, str) and value.strip() else fallback


def _is_reparse_point(info: Any) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _history_directory(root: Path) -> Path | None:
    directory = root
    for part in (".factory", "deep-runs"):
        directory /= part
        try:
            info = directory.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISDIR(info.st_mode) or _is_reparse_point(info):
            raise ValueError("linked or invalid deep-run history")
    return directory


def _valid_run_directory(path: Path, info: Any) -> bool:
    valid_name = len(path.name) == 32 and all(
        char in "0123456789abcdef" for char in path.name
    )
    return valid_name and stat.S_ISDIR(info.st_mode) and not _is_reparse_point(info)


def _run_entry(path: Path) -> tuple[int, str, str]:
    info = path.lstat()
    if not _valid_run_directory(path, info):
        raise ValueError("invalid deep-run entry")
    state_info = (path / "state.json").lstat()
    if not stat.S_ISREG(state_info.st_mode) or _is_reparse_point(state_info):
        raise ValueError("invalid deep-run state")
    source = f".factory/deep-runs/{path.name}/state.json"
    return state_info.st_mtime_ns, path.name, source


def _latest_run(root: Path) -> tuple[str, str] | None:
    directory = _history_directory(root)
    if directory is None:
        return None
    entries = list(islice(directory.iterdir(), 129))
    if len(entries) > 128:
        raise ValueError("deep-run history exceeds inspection bound")
    runs = [_run_entry(path) for path in entries]
    if not runs:
        return None
    _, run_id, source = max(runs)
    return run_id, source


def _run_lists(run: dict[str, Any]) -> tuple[list[Any], list[Any]]:
    lanes, gaps = run.get("lanes"), run.get("gaps")
    if (
        not isinstance(lanes, list)
        or len(lanes) > 32
        or not isinstance(gaps, list)
        or len(gaps) > 256
    ):
        raise ValueError("deep-run summary exceeds UI inspection bound")
    return lanes, gaps


def _top_level_gaps(gaps: list[Any], coverage: list[dict[str, Any]]) -> int:
    for gap in gaps:
        if not isinstance(gap, dict):
            raise ValueError("invalid deep-run coverage gap")
        if len(coverage) < 20:
            coverage.append(
                {
                    "code": _label(gap.get("code"), "UNKNOWN_GAP"),
                    "path": _label(gap.get("path"), "."),
                    "action": _label(gap.get("action"), "Inspect the run and retry."),
                }
            )
    return len(gaps)


def _lane_values(lane: Any) -> tuple[str, str, list[Any], list[Any]]:
    if (
        not isinstance(lane, dict)
        or not isinstance(lane.get("findings"), list)
        or not isinstance(lane.get("gaps"), list)
    ):
        raise ValueError("invalid deep-run lane")
    return (
        _label(lane.get("lane_id"), "unknown"),
        _label(lane.get("state"), "INCOMPLETE"),
        lane["findings"],
        lane["gaps"],
    )


def _lane_summary(
    lane_id: str, state: str, findings: list[Any], gaps: list[Any]
) -> dict[str, Any]:
    return {
        "lane_id": lane_id,
        "state": state,
        "finding_count": len(findings),
        "gaps": [_label(code, "UNKNOWN_GAP") for code in gaps[:20]],
    }


def _trace_observation(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict) or not isinstance(item.get("lines"), list):
        raise ValueError("invalid source-trace observation")
    lines = item["lines"]
    if len(lines) > 50000 or any(type(n) is not int or n < 1 for n in lines):
        raise ValueError("invalid source-trace lines")
    path = item.get("path")
    if not isinstance(path, str) or "\\" in path or ":" in path:
        raise ValueError("invalid source-trace path")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError("invalid source-trace path")
    return {
        "route_id": _label(item.get("route_id"), "unknown"),
        "path": _label(path, "unknown"),
        "source_sha256": _label(item.get("source_sha256"), "missing"),
        "lines": lines[:100],
        "line_count": len(lines),
        "truncated": len(lines) > 100,
    }


def _trace_parts(native: dict[str, Any]) -> tuple[dict[str, Any], list, list]:
    trace = native.get("source_trace")
    if trace is not None and not isinstance(trace, dict):
        raise ValueError("invalid source trace")
    missing = native.get("source_trace_missing", [])
    if not isinstance(missing, list) or len(missing) > 50000:
        raise ValueError("invalid missing source-trace bindings")
    observations = (trace or {}).get("observations", [])
    if not isinstance(observations, list) or len(observations) > 50000:
        raise ValueError("invalid source-trace observations")
    return trace or {}, missing, observations


def _trace_replay_matches(native: dict[str, Any], trace: dict[str, Any]) -> bool:
    replay = native.get("candidate_replay")
    repeated = replay.get("source_trace") if isinstance(replay, dict) else None
    if not isinstance(repeated, dict) or not trace:
        return False
    keys = (
        "schema",
        "run_id",
        "candidate_sha256",
        "profile_sha256",
        "target_sha256",
        "provider",
    )
    identities_match = all(
        isinstance(trace.get(key), str)
        and bool(trace[key])
        and trace[key] == repeated.get(key)
        for key in keys
    )
    return (
        identities_match
        and bool(trace.get("observations"))
        and trace["observations"] == repeated.get("observations")
    )


def _missing_trace_bindings(missing: list) -> list[dict[str, str]]:
    rows = [_trace_observation({**item, "lines": []}) for item in missing[:20]]
    return [{"route_id": row["route_id"], "path": row["path"]} for row in rows]


def _source_trace_summary(lane: dict[str, Any]) -> dict[str, Any] | None:
    native = lane.get("native_execution")
    if not isinstance(native, dict):
        return None
    trace, missing, observations = _trace_parts(native)
    error = native.get("source_trace_error")
    if not trace and not error and not missing:
        return None
    visible = [_trace_observation(item) for item in observations[:20]]
    return {
        "provider": _label(trace.get("provider"), "missing"),
        "raw_sha256": _label(trace.get("raw_sha256"), "missing"),
        "observations": visible,
        "observation_count": len(observations),
        "missing_binding_count": len(missing),
        "missing_bindings": _missing_trace_bindings(missing),
        "error": _label(error, "UNKNOWN_TRACE_ERROR") if error else None,
        "replay_matches": _trace_replay_matches(native, trace),
        "cleanup_confirmed": native.get("cleanup_confirmed") is True,
        "truncated": len(observations) > 20
        or len(missing) > 20
        or any(item["truncated"] for item in visible),
        "claim_boundary": "Request-associated observed lines only; not full branches, authenticity, vulnerability causality or detection accuracy. Local self-hash observations are not signed validation.",
    }


def _lane_coverage_gaps(
    gaps: list[Any], lane_id: str, coverage: list[dict[str, Any]]
) -> int:
    for code in gaps:
        if len(coverage) < 20:
            coverage.append(
                {
                    "code": _label(code, "UNKNOWN_GAP"),
                    "path": lane_id,
                    "action": "Resolve the analyzer prerequisite and rerun the signed scan.",
                }
            )
    return len(gaps)


def _repair_task(finding: Any) -> dict[str, Any]:
    if not isinstance(finding, dict):
        raise ValueError("invalid deep-run finding")
    return {
        "finding_id": _label(finding.get("finding_id"), "unknown"),
        "rule_id": _label(finding.get("rule_id"), "unknown"),
        "severity": _label(finding.get("severity"), "unknown"),
        "path": _label(finding.get("path"), "unknown"),
        "line": finding.get("line") if type(finding.get("line")) is int else None,
        "source_sha256": finding.get("source_sha256"),
        "remediation": _label(
            finding.get("remediation"), "Inspect and repair this finding."
        ),
    }


def _append_repair_tasks(findings: list[Any], repairs: list[dict[str, Any]]) -> None:
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("invalid deep-run finding")
        if len(repairs) < 20:
            repairs.append(_repair_task(finding))


def _run_details(run: dict[str, Any]) -> dict[str, Any]:
    lanes, gaps = _run_lists(run)
    lane_summaries: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    repairs: list[dict[str, Any]] = []
    coverage_gap_count = _top_level_gaps(gaps, coverage_gaps)
    finding_count = 0
    for lane in lanes:
        lane_id, state, findings, lane_gaps = _lane_values(lane)
        summary = _lane_summary(lane_id, state, findings, lane_gaps)
        trace = _source_trace_summary(lane)
        if trace is not None:
            summary["source_trace"] = trace
        lane_summaries.append(summary)
        coverage_gap_count += _lane_coverage_gaps(lane_gaps, lane_id, coverage_gaps)
        finding_count += len(findings)
        _append_repair_tasks(findings, repairs)
    return {
        "lanes": lane_summaries,
        "coverage_gaps": coverage_gaps,
        "coverage_gap_count": coverage_gap_count,
        "repair_tasks": repairs,
        "finding_count": finding_count,
        "truncated": coverage_gap_count > len(coverage_gaps)
        or finding_count > len(repairs),
    }


def deep_scan_projection(root: Path) -> tuple[dict[str, Any], str | None]:
    """Return one local run summary and an optional Graph Ops source error code."""
    projection: dict[str, Any] = {
        "state": "NOT_RUN",
        "run_id": None,
        "source": None,
        "state_content_sha256": None,
        "candidate_sha256": None,
        "candidate_binding": "RECORDED_HASH_NOT_CURRENT",
        "observed_state": None,
        "analysis_complete": False,
        "lanes": [],
        "coverage_gaps": [],
        "coverage_gap_count": 0,
        "repair_tasks": [],
        "finding_count": 0,
        "truncated": False,
        "verification": "self_hash_only_not_signature_or_freshness",
        "authority": "none",
        "status_limit": "No local deep scan has been observed.",
    }
    try:
        selected = _latest_run(Path(root).resolve())
        if selected is None:
            return projection, None
        from .deep_audit import deep_run_status
        from .deep_audit_io import digest, read_run_json, run_directory

        run_id, source = selected
        directory = run_directory(root, run_id)
        document = read_run_json(directory, "state.json")
        sequence = document.get("sequence")
        if type(sequence) is not int or sequence > 1024:
            raise ValueError("deep-run event count exceeds UI inspection bound")
        run = deep_run_status(root, run_id)
        if (run.get("sequence"), run.get("event_sha256")) != (
            sequence,
            document.get("event_sha256"),
        ):
            raise ValueError("deep-run state changed during inspection")
        projection.update(
            state="INCOMPLETE",
            run_id=run_id,
            source=source,
            state_content_sha256=digest(document),
            candidate_sha256=run.get("candidate_sha256"),
            observed_state=run.get("observed_state"),
            analysis_complete=run.get("analysis_complete") is True,
            status_limit=run.get("status_limit"),
        )
        projection.update(_run_details(run))
    except (OSError, ValueError, KeyError, TypeError):
        projection["state"] = "INCOMPLETE"
        projection["status_limit"] = (
            "Local deep-run history could not be verified within UI bounds. "
            "Inspect with factory deep-audit progress."
        )
        return projection, "DEEP_RUN_STATUS_INVALID"
    return projection, None


REPORT_PATH = Path(".factory/test-reports/pytest.xml")
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_CASES = 10_000
MAX_XML_DEPTH = 64


class _DepthLimitError(ValueError):
    """Raised when a report exceeds the bounded XML nesting depth."""


class _CountMismatch(ValueError):
    """Raised when declared suite outcomes omit or contradict parsed cases."""


class _UnknownTestStatus(ValueError):
    """Raised when a runner supplies an outcome this reader cannot classify."""


def _base_snapshot() -> dict:
    return {
        "state": "NOT_RUN",
        "counts": {"passed": 0, "failed": 0, "error": 0, "skipped": 0},
        "total_count": 0,
        "cases": [],
        "source": REPORT_PATH.as_posix(),
        "source_sha256": None,
        "report_time": None,
        "source_mtime_utc": None,
        "truncated": False,
        "limits": {
            "max_bytes": MAX_REPORT_BYTES,
            "max_cases": MAX_CASES,
            "max_xml_depth": MAX_XML_DEPTH,
        },
        "candidate_binding": "UNBOUND",
        "reason": "No test report was found at the documented path.",
    }


def _bounded(value: object, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _local_tag(tag: object) -> str:
    return str(tag).rsplit("}", 1)[-1]


def _duration(value: object) -> float | None:
    try:
        duration = float(str(value))
    except (TypeError, ValueError):
        return None
    if duration != duration or duration < 0 or duration == float("inf"):
        return None
    return duration


def _line(value: object) -> int | None:
    try:
        line = int(str(value))
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def _case_result(
    element: ElementTree.Element,
) -> tuple[str, ElementTree.Element | None]:
    markers = {_local_tag(child.tag): child for child in element}
    if "error" in markers:
        return "error", markers["error"]
    elif "failure" in markers:
        return "failed", markers["failure"]
    elif "skipped" in markers:
        return "skipped", markers["skipped"]
    declared_status = str(element.get("status") or "passed").lower()
    if declared_status not in {"passed", "failed", "error", "skipped"}:
        raise _UnknownTestStatus
    return declared_status, None


def _case_failure_summary(result: ElementTree.Element | None) -> str | None:
    if result is None:
        return None
    return _bounded(result.get("message") or result.text, 400) or None


def _case(element: ElementTree.Element, suite_name: str) -> dict:
    status, result = _case_result(element)
    return {
        "suite": _bounded(element.get("classname") or suite_name, 240),
        "name": _bounded(element.get("name"), 300),
        "status": status,
        "file": _bounded(element.get("file"), 500) or None,
        "line": _line(element.get("line")),
        "duration_seconds": _duration(element.get("time")),
        "failure_summary": _case_failure_summary(result),
    }


def _declared_count(value: object) -> int | None:
    if value is None:
        return None
    try:
        number = int(str(value))
    except (TypeError, ValueError) as exc:
        raise _CountMismatch from exc
    if number < 0:
        raise _CountMismatch
    return number


def _read_junit_content(root: Path, snapshot: dict) -> bytes | None:
    """Read one bounded report from a path contained by the workspace."""
    try:
        workspace = root.resolve()
        source = (workspace / REPORT_PATH).resolve()
        source.relative_to(workspace)
    except (OSError, RuntimeError, ValueError):
        snapshot.update(
            state="INCOMPLETE",
            reason="The report path escapes the workspace or cannot be resolved.",
        )
        return None

    try:
        if not source.exists():
            return None
        if not source.is_file():
            snapshot.update(
                state="INCOMPLETE", reason="The report path is not a regular file."
            )
            return None
        with source.open("rb") as handle:
            content = handle.read(MAX_REPORT_BYTES + 1)
            metadata = fstat(handle.fileno())
    except OSError:
        snapshot.update(state="INCOMPLETE", reason="The report could not be read.")
        return None

    snapshot["source_mtime_utc"] = (
        datetime.fromtimestamp(metadata.st_mtime, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    if len(content) > MAX_REPORT_BYTES:
        snapshot.update(
            state="INCOMPLETE",
            truncated=True,
            reason="The report exceeds the byte limit; no partial file was parsed.",
        )
        return None
    snapshot["source_sha256"] = sha256(content).hexdigest()
    return content


def _validate_junit_content(content: bytes, snapshot: dict) -> bool:
    """Reject unsupported encodings and entity expansion before XML parsing."""
    try:
        content.decode("utf-8-sig")
    except UnicodeError:
        snapshot.update(
            state="INCOMPLETE", reason="The XML report must be UTF-8 encoded."
        )
        return False
    if b"\x00" in content:
        snapshot.update(state="INCOMPLETE", reason="The XML report contains NUL bytes.")
        return False
    if b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
        snapshot.update(
            state="INCOMPLETE",
            reason="XML declarations with entities or DTDs are not accepted.",
        )
        return False
    return True


@dataclass
class _JUnitParseState:
    """Declared counts and suite nesting observed while streaming one report."""

    depth: int = 0
    suite_names: list[str] = field(default_factory=list)
    suite_checks: list[tuple[int, dict[str, int], dict[str, int | None]]] = field(
        default_factory=list
    )
    declared: int | None = None
    declared_results: dict[str, int] = field(default_factory=dict)
    root_tag: str | None = None


def _junit_suite_start(
    element: ElementTree.Element, snapshot: dict, state: _JUnitParseState
) -> None:
    """Record a suite's declared outcomes before counting its cases."""
    state.suite_names.append(_bounded(element.get("name"), 240))
    state.suite_checks.append(
        (
            snapshot["total_count"],
            dict(snapshot["counts"]),
            {
                "tests": _declared_count(element.get("tests")),
                "failed": _declared_count(element.get("failures")),
                "error": _declared_count(element.get("errors")),
                "skipped": _declared_count(element.get("skipped")),
            },
        )
    )
    if snapshot["report_time"] is None:
        snapshot["report_time"] = _bounded(element.get("timestamp"), 80) or None


def _junit_start(
    tag: str, element: ElementTree.Element, snapshot: dict, state: _JUnitParseState
) -> None:
    """Enforce nesting bounds and read root and suite declarations."""
    state.depth += 1
    if state.depth > MAX_XML_DEPTH:
        raise _DepthLimitError
    if state.depth == 1:
        state.root_tag = tag
        state.declared = _declared_count(element.get("tests"))
        for attribute, status in (
            ("failures", "failed"),
            ("errors", "error"),
            ("skipped", "skipped"),
        ):
            count = _declared_count(element.get(attribute))
            if count is not None:
                state.declared_results[status] = count
        snapshot["report_time"] = _bounded(element.get("timestamp"), 80) or None
    if tag == "testsuite":
        _junit_suite_start(element, snapshot, state)


def _junit_suite_end(
    element: ElementTree.Element, snapshot: dict, state: _JUnitParseState
) -> None:
    """Require each suite's parsed cases to match its declared counts."""
    before_total, before_counts, suite_declared = state.suite_checks.pop()
    if suite_declared["tests"] is not None and (
        snapshot["total_count"] - before_total != suite_declared["tests"]
    ):
        raise _CountMismatch
    if any(
        count is not None
        and snapshot["counts"][status] - before_counts[status] != count
        for status, count in suite_declared.items()
        if status != "tests"
    ):
        raise _CountMismatch
    if state.suite_names:
        state.suite_names.pop()
    element.clear()


def _junit_end(
    tag: str, element: ElementTree.Element, snapshot: dict, state: _JUnitParseState
) -> None:
    """Count test cases and close a suite after validating its declaration."""
    if tag == "testcase":
        case = _case(element, state.suite_names[-1] if state.suite_names else "")
        snapshot["counts"][case["status"]] += 1
        snapshot["total_count"] += 1
        if len(snapshot["cases"]) < MAX_CASES:
            snapshot["cases"].append(case)
        else:
            snapshot["truncated"] = True
        element.clear()
    elif tag == "testsuite":
        _junit_suite_end(element, snapshot, state)
    state.depth -= 1


def _parse_junit_xml(content: bytes, snapshot: dict) -> _JUnitParseState:
    """Stream bounded XML into a case snapshot and declaration state."""
    state = _JUnitParseState()
    for event, element in ElementTree.iterparse(
        BytesIO(content), events=("start", "end")
    ):
        tag = _local_tag(element.tag)
        if event == "start":
            _junit_start(tag, element, snapshot, state)
        else:
            _junit_end(tag, element, snapshot, state)
    return state


def _junit_parse_failure(snapshot: dict, exc: Exception) -> None:
    """Discard partial cases and explain the failed XML interpretation."""
    snapshot.update(
        state="INCOMPLETE",
        counts={"passed": 0, "failed": 0, "error": 0, "skipped": 0},
        total_count=0,
        cases=[],
        truncated=False,
        reason=(
            "The XML nesting depth exceeds the limit."
            if isinstance(exc, _DepthLimitError)
            else "Declared JUnit counts differ from parsed cases."
            if isinstance(exc, _CountMismatch)
            else "A JUnit test case has an unrecognized status."
            if isinstance(exc, _UnknownTestStatus)
            else "The XML report is malformed."
        ),
    )


def _finalize_junit_snapshot(snapshot: dict, state: _JUnitParseState) -> None:
    """Reconcile the parsed cases with root declarations and display limits."""
    if state.root_tag not in {"testsuite", "testsuites"}:
        snapshot.update(
            state="INCOMPLETE",
            reason="The XML root is not a JUnit testsuite or testsuites element.",
        )
    elif snapshot["truncated"]:
        snapshot.update(
            state="INCOMPLETE",
            reason="Some cases exceed the display limit; the complete count remains visible.",
        )
    elif state.declared is not None and state.declared != snapshot["total_count"]:
        snapshot.update(
            state="INCOMPLETE",
            reason="The declared test count differs from parsed test cases.",
        )
    elif any(
        snapshot["counts"][status] != count
        for status, count in state.declared_results.items()
    ):
        snapshot.update(
            state="INCOMPLETE",
            reason="Declared test outcomes differ from parsed case outcomes.",
        )
    else:
        snapshot.update(
            state="OBSERVED",
            reason="Report cases were read; this report is not bound to the current candidate.",
        )


def read_junit_report(root: Path) -> dict:
    """Read one local JUnit XML report and retain every case within limits.

    ``INCOMPLETE`` means the report is unreadable, malformed, inconsistent, or
    exceeds a stated limit. The function never executes code or follows a
    report path outside the resolved workspace. Case metadata is untrusted.
    """
    snapshot = _base_snapshot()
    content = _read_junit_content(root, snapshot)
    if content is None or not _validate_junit_content(content, snapshot):
        return snapshot
    try:
        state = _parse_junit_xml(content, snapshot)
    except (
        _DepthLimitError,
        _CountMismatch,
        _UnknownTestStatus,
        ElementTree.ParseError,
        ValueError,
    ) as exc:
        _junit_parse_failure(snapshot, exc)
        return snapshot
    _finalize_junit_snapshot(snapshot, state)
    return snapshot


def _fuzz_snapshot(
    cov, contract: dict, harness: str, output: _deep_audit_io.Path, state: dict
) -> None:
    raw_path = output.with_suffix(".coverage.json")
    cov.json_report(outfile=str(raw_path))
    raw = _deep_audit_io.strict_json(raw_path.read_bytes())
    sources = {item["path"]: item["sha256"] for item in contract["inventory"]["files"]}
    edges = sum(
        len(item.get("executed_branches", [])) for item in raw["files"].values()
    )
    corpus = _deep_audit_io._fuzz_corpus_document(state, harness, sources[harness])
    corpus_raw = _deep_audit_io.canonical_bytes(corpus)
    output.with_suffix(".corpus.json").write_bytes(corpus_raw)
    report = {
        "schema": "factory.deep-atheris-observations.v1",
        "engine": "atheris",
        "tool_version": contract["lane"]["tool_version"],
        "completed": state.get("completed", False),
        "errors": state.get("errors", []),
        "harness": {"path": harness, "sha256": sources[harness]},
        "metrics": {
            "executions": state["executions"],
            "corpus_size": len(state["inputs"]),
            "coverage_edges": edges,
        },
        "metric_definitions": {
            "executions": "observed callbacks (lower bound at last snapshot)",
            "corpus_size": "distinct executed inputs retained in the bounded local corpus",
            "coverage_edges": "executed Python branch arcs from coverage.py",
        },
        "findings": state["findings"],
        "source_coverage": _deep_audit_io._native_source_counts(raw, sources),
        "coverage_native_sha256": _deep_audit_io.digest(raw),
        "corpus": {
            "sha256": _deep_audit_io.sha256_bytes(corpus_raw),
            "inputs": len(corpus["inputs"]),
            "bytes": state.get("corpus_bytes", 0),
        },
        "control_sha256": state.get("control_sha256"),
    }
    output.write_bytes(_deep_audit_io.canonical_bytes(report))


def _fuzz_record_input(state, data):
    import base64

    fingerprint = _deep_audit_io.sha256_bytes(data)
    new_bytes = len(data) if fingerprint not in state["inputs"] else 0
    limits = (
        len(data) > 1_048_576,
        state["executions"] >= 1_000_000,
        fingerprint not in state["inputs"] and len(state["inputs"]) >= 4096,
        state.get("corpus_bytes", 0) + new_bytes > 2_097_152,
    )
    if any(limits):
        state.update(completed=False, errors=["E_FUZZ_BUDGET"])
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_BUDGET", "bounded fuzz observation budget exhausted"
        )
    state["executions"] += 1
    state["inputs"].add(fingerprint)
    state.setdefault("corpus", {})[fingerprint] = {
        "sha256": fingerprint,
        "bytes": len(data),
        "data_base64": base64.b64encode(data).decode("ascii"),
    }
    state["corpus_bytes"] = state.get("corpus_bytes", 0) + new_bytes


def _fuzz_corpus_document(state, harness, source_sha):
    corpus = state.get("corpus", {})
    if set(corpus) != state["inputs"]:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_CORPUS", "recorded inputs and corpus differ"
        )
    return {
        "schema": "factory.fuzz-corpus.v1",
        "harness": {"path": harness, "sha256": source_sha},
        "inputs": [corpus[key] for key in sorted(corpus)],
    }


def _fuzz_corpus_entry(entry):
    import base64

    if not isinstance(entry, dict) or set(entry) != {"sha256", "bytes", "data_base64"}:
        raise ValueError("exact corpus entry fields required")
    size = _deep_audit_io.require_int(
        entry["bytes"], "input bytes", minimum=0, maximum=1_048_576
    )
    encoded = entry["data_base64"]
    if not isinstance(encoded, str) or len(encoded) > 1_398_104:
        raise ValueError("bounded input required")
    data = base64.b64decode(encoded, validate=True)
    if (
        len(data) != size
        or base64.b64encode(data).decode("ascii") != encoded
        or _deep_audit_io.sha256_bytes(data) != entry["sha256"]
    ):
        raise ValueError("corpus input differs")
    return size


def _validate_fuzz_corpus(raw, report, sources):
    try:
        corpus = _deep_audit_io.strict_json(raw)
        if set(corpus) != {"schema", "harness", "inputs"}:
            raise ValueError("exact corpus fields required")
        if (
            corpus["schema"] != "factory.fuzz-corpus.v1"
            or _deep_audit_io.canonical_bytes(corpus) != raw
        ):
            raise ValueError("canonical corpus required")
        harness = corpus["harness"]
        if (
            set(harness) != {"path", "sha256"}
            or harness != report["harness"]
            or sources[_deep_audit_io.relative_path(harness["path"])]
            != harness["sha256"]
        ):
            raise ValueError("harness binding differs")
        _deep_audit_io._validate_fuzz_corpus_inputs(corpus["inputs"], report, raw)
        return corpus
    except (
        _deep_audit_io.RuntimeAuditError,
        ValueError,
        TypeError,
        KeyError,
        UnicodeError,
    ) as error:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_CORPUS", "invalid retained fuzz corpus"
        ) from error


def _validate_fuzz_corpus_inputs(inputs, report, raw):
    if not isinstance(inputs, list) or not 1 <= len(inputs) <= 4096:
        raise ValueError("bounded nonempty corpus required")
    sizes = [_deep_audit_io._fuzz_corpus_entry(entry) for entry in inputs]
    hashes = [entry["sha256"] for entry in inputs]
    if hashes != sorted(set(hashes)) or sum(sizes) > 2_097_152:
        raise ValueError("corpus uniqueness or budget differs")
    expected = {
        "sha256": _deep_audit_io.sha256_bytes(raw),
        "inputs": len(inputs),
        "bytes": sum(sizes),
    }
    _deep_audit_io.require_int(
        report["corpus"]["inputs"], "retained inputs", minimum=1, maximum=4096
    )
    _deep_audit_io.require_int(
        report["corpus"]["bytes"], "retained bytes", minimum=0, maximum=2_097_152
    )
    _deep_audit_io.require_int(
        report["metrics"]["executions"], "callbacks", minimum=1, maximum=1_000_000
    )
    if report["corpus"] != expected or report["metrics"]["corpus_size"] != len(inputs):
        raise ValueError("corpus accounting differs")
    if report["metrics"]["executions"] < len(inputs):
        raise ValueError("corpus exceeds observed callbacks")
    for finding in report["findings"]:
        if finding.get("input_sha256") not in hashes:
            raise ValueError("failure input is not retained")


def _fuzz_replay_expected(request, validated_controls=None):
    keys = {"lane", "inventory", "coverage", "report"}
    if isinstance(request, dict) and {"challenges", "obligations"} <= set(request):
        keys |= {"challenges", "obligations"}
    _deep_audit_io.exact_keys(request, keys)
    lane, inventory, report = request["lane"], request["inventory"], request["report"]
    if lane["engine"] != "atheris" or lane["family"] != "fuzz":
        raise _deep_audit_io.RuntimeAuditError("E_FUZZ_REPLAY", "fuzz lane required")
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    corpus = _deep_audit_io._retained_fuzz_corpus(report, sources)
    expected = {
        "schema": "factory.fuzz-native-replay.v1",
        "state": "VERIFIED",
        "candidate_sha256": _deep_audit_io.require_digest(
            inventory["candidate_sha256"], "candidate"
        ),
        "lane_sha256": _deep_audit_io.digest(lane),
        "coverage_sha256": _deep_audit_io.digest(request["coverage"]),
        "report_sha256": _deep_audit_io.digest(report),
        "corpus_sha256": report["corpus"]["sha256"],
        "harness": corpus["harness"],
        "replayed_inputs": len(corpus["inputs"]),
        "failure_inputs": sorted({item["input_sha256"] for item in report["findings"]}),
    }
    if "obligations" in request:
        controls = validated_controls or _deep_audit_io.verify_fuzz_retained_evidence(
            request["challenges"],
            request["obligations"],
            lane,
            sources,
            inventory["candidate_sha256"],
            request["coverage"],
        )
        expected.update(controls[0])
    return expected


def _fuzz_replay_inputs_main(request_path, source):
    """Image-owned driver; replay unique retained inputs in canonical hash order."""
    import base64
    import importlib.util

    with _deep_audit_io.Path(request_path).open("rb") as stream:
        request = _deep_audit_io.strict_json(stream.read(_deep_audit_io.LIMIT + 1))
    retained_controls = None
    if "obligations" in request:
        retained_controls = _deep_audit_io.verify_fuzz_retained_evidence(
            request["challenges"],
            request["obligations"],
            request["lane"],
            {item["path"]: item["sha256"] for item in request["inventory"]["files"]},
            request["inventory"]["candidate_sha256"],
            request["coverage"],
        )
    expected = _deep_audit_io._fuzz_replay_expected(request, retained_controls)
    sources = {item["path"]: item["sha256"] for item in request["inventory"]["files"]}
    corpus = _deep_audit_io._retained_fuzz_corpus(request["report"], sources)
    path = _deep_audit_io.local_file(
        _deep_audit_io.Path(source), corpus["harness"]["path"]
    )
    _deep_audit_io.bound_bytes(_deep_audit_io.Path(source), corpus["harness"])
    spec = importlib.util.spec_from_file_location("factory_fuzz_replay_target", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    failures = _deep_audit_io._fuzz_replay_harness(module, corpus["inputs"], base64)
    result = {
        "schema": "factory.fuzz-input-replay.v1",
        "harness": expected["harness"],
        "corpus_sha256": expected["corpus_sha256"],
        "replayed_inputs": len(corpus["inputs"]),
        "failure_inputs": sorted(failures),
    }
    if "obligations" in request:
        result["controls"] = _deep_audit_io._fuzz_replay_controls(
            retained_controls[1], source, base64
        )
    return result


def _fuzz_replay_harness(module, inputs, base64):
    failures = []
    for entry in inputs:
        try:
            module.TestOneInput(base64.b64decode(entry["data_base64"], validate=True))
        except Exception:
            failures.append(entry["sha256"])
    return failures


def _fuzz_replay_controls(controls, source, base64):
    results = []
    for control in controls:
        module = _deep_audit_io._fuzz_replay_module(source, control)
        failures = _deep_audit_io._fuzz_replay_harness(
            module, control["corpus"]["inputs"], base64
        )
        reported = sorted(
            {item["input_sha256"] for item in control["report"]["findings"]}
        )
        enabled = _deep_audit_io._fuzz_control_ids(control["config"]) == [
            "FUZZ_EXCEPTION"
        ]
        detected = failures if enabled else []
        results.append(
            {
                "obligation_id": control["obligation_id"],
                "kind": control["kind"],
                "failure_inputs": sorted(failures),
                "detector_inputs": sorted(detected),
                "retained_failure_inputs": reported,
            }
        )
    return results


def _fuzz_replay_module(source, control):
    import importlib.util

    path = _deep_audit_io.local_file(source, control["harness"]["path"])
    _deep_audit_io.bound_bytes(source, control["harness"])
    module_name = "factory_fuzz_control_" + control["obligation_id"]
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPLAY", "control harness cannot be loaded"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "TestOneInput", None)):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPLAY", "control callback is missing"
        )
    return module


def _fuzz_replay_profile(request):
    profile = _deep_audit_io.strict_json(
        _deep_audit_io.Path("/opt/factory/adapter-profile.json").read_bytes()
    )
    lane, coverage = request["lane"], request["coverage"]
    _deep_audit_io._native_profile(profile, lane)
    expected = {
        "profile_sha256": _deep_audit_io.digest(profile),
        "image_binding_sha256": _deep_audit_io.sha256_bytes(
            lane["image"].encode("utf-8")
        ),
        "tool_version": profile["tool_version"],
        "ruleset_sha256": profile["ruleset_sha256"],
    }
    if any(coverage.get(key) != value for key, value in expected.items()):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPLAY", "pinned fuzz profile binding differs"
        )


def execute_fuzz_native_replay(request, source, scratch, timeout):
    """Re-execute retained fuzz inputs under a bounded isolated worker lifecycle."""
    from .runtime_audit_process import run_bounded_command

    retained_controls = _deep_audit_io._fuzz_replay_control_evidence(request)
    expected = _deep_audit_io._fuzz_replay_expected(request, retained_controls)
    timeout = _deep_audit_io.require_int(
        timeout, "fuzz replay timeout", minimum=1, maximum=3600
    )
    deadline = _deep_audit_io.time.monotonic() + timeout
    _deep_audit_io._fuzz_replay_profile(request)
    _deep_audit_io._adapter_sources(source, request["inventory"])
    contract = scratch / "fuzz-replay-input.json"
    contract.write_bytes(_deep_audit_io.canonical_bytes(request))
    capture = scratch / "fuzz-replay-output.json"
    runtime = str(_deep_audit_io.Path(__file__).resolve().parent.parent)
    program = (
        "import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);"
        "from factoryline.deep_audit_io import _fuzz_replay_inputs_main;"
        "print(json.dumps(_fuzz_replay_inputs_main(sys.argv[2],Path(sys.argv[3]))),flush=True)"
    )
    facts = run_bounded_command(
        [
            "/usr/local/bin/python",
            "-I",
            "-c",
            program,
            runtime,
            str(contract),
            str(source),
        ],
        source,
        _deep_audit_io._fuzz_replay_remaining(deadline),
        scratch,
        stdout_path=capture,
    )
    with capture.open("rb") as stream:
        raw = stream.read(_deep_audit_io.LIMIT + 1)
    _deep_audit_io._validate_fuzz_replay_observation(
        raw, facts, expected, retained_controls[1] if retained_controls else None
    )
    _deep_audit_io._adapter_sources(source, request["inventory"])
    _deep_audit_io._fuzz_replay_remaining(deadline)
    return {**expected, "native_execution_sha256": _deep_audit_io.digest(facts)}


def _fuzz_replay_remaining(deadline):
    remaining = int(deadline - _deep_audit_io.time.monotonic())
    if remaining < 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPLAY", "fuzz replay deadline exhausted"
        )
    return remaining


def _validate_fuzz_replay_observation(raw, facts, expected, controls=None):
    from .runtime_audit_common import _validate_runner_facts

    _validate_runner_facts(facts, facts["timeout_seconds"])
    if _deep_audit_io._adapter_command_failed(facts, [0], float("inf")) or facts.get(
        "cancelled"
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPLAY", "fuzz replay process failed"
        )
    if (
        _deep_audit_io.sha256_bytes(raw) != facts["stdout_sha256"]
        or len(raw) != facts["stdout_bytes"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPLAY", "fuzz replay stream differs"
        )
    observed = _deep_audit_io.strict_json(raw)
    _deep_audit_io.require_int(
        observed.get("replayed_inputs"), "replayed inputs", minimum=1, maximum=4096
    )
    fields = {
        key: expected[key]
        for key in ("harness", "corpus_sha256", "replayed_inputs", "failure_inputs")
    }
    expected_observation = {"schema": "factory.fuzz-input-replay.v1", **fields}
    if controls is not None:
        expected_observation["controls"] = observed.get("controls")
        _deep_audit_io._validate_fuzz_replayed_controls(
            observed.get("controls"), controls
        )
    if observed != expected_observation:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPLAY", "retained input outcomes differ"
        )


def _validate_fuzz_replayed_controls(observed, controls):
    if not isinstance(observed, list) or len(observed) != len(controls):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPLAY", "retained controls are incomplete"
        )
    for actual, expected in zip(observed, controls):
        if not isinstance(actual, dict) or set(actual) != {
            "obligation_id",
            "kind",
            "failure_inputs",
            "detector_inputs",
            "retained_failure_inputs",
        }:
            raise _deep_audit_io.RuntimeAuditError(
                "E_FUZZ_REPLAY", "control replay shape differs"
            )
        _deep_audit_io._validate_fuzz_replayed_control(actual, expected)


def _validate_fuzz_replayed_control(actual, expected):
    kind = expected["kind"]
    failures = actual["failure_inputs"]
    retained = expected["retained_failure_inputs"]
    if (
        actual["obligation_id"] != expected["obligation_id"]
        or kind != actual["kind"]
        or actual["retained_failure_inputs"] != retained
        or not _deep_audit_io._fuzz_replayed_failure_inputs_valid(failures, expected)
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPLAY", "control exception replay differs"
        )
    detected = failures if expected["detector_enabled"] else []
    if actual["detector_inputs"] != detected:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPLAY", "control detector result differs"
        )


def _fuzz_replayed_failure_inputs_valid(failures, expected):
    if not isinstance(failures, list) or any(
        not _deep_audit_io._is_digest(item) for item in failures
    ):
        return False
    if failures != sorted(set(failures)):
        return False
    if not set(failures) <= expected["corpus_hashes"]:
        return False
    kind = expected["kind"]
    if kind == "positive":
        return failures == expected["retained_failure_inputs"]
    if kind == "negative":
        return not failures
    return kind == "mutation" and bool(failures)


def _is_digest(value):
    return (
        isinstance(value, str)
        and _deep_audit_io.re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _finalize_fuzz_report(raw, invocations):
    from .runtime_audit_common import _validate_runner_facts

    if len(invocations) != 1 or raw.get("errors") != []:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPORT", "one successful bounded fuzz lifecycle required"
        )
    facts = invocations[0]["execution"]
    _validate_runner_facts(facts, facts["timeout_seconds"])
    expected = 77 if raw.get("findings") else 0
    failures = (
        facts.get(key)
        for key in ("timed_out", "launch_error", "output_limit_exceeded", "cancelled")
    )
    if (
        any(failures)
        or not facts["cleanup_confirmed"]
        or facts["exit_code"] != expected
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPORT", "fuzz result and process termination differ"
        )
    report = dict(raw)
    report.update(
        completed=True, lifecycle_execution_sha256=_deep_audit_io.digest(facts)
    )
    return report


def _fuzz_control_ids(raw):
    value = _deep_audit_io.strict_json(raw)
    if (
        _deep_audit_io.canonical_bytes(value) != raw
        or set(value) != {"schema", "rules"}
        or value["schema"] != "factory.fuzz-control.v1"
        or not isinstance(value["rules"], dict)
        or set(value["rules"]) != {"FUZZ_EXCEPTION"}
        or type(value["rules"]["FUZZ_EXCEPTION"]) is not bool
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_CONTROL", "canonical exact fuzz rule config required"
        )
    return ["FUZZ_EXCEPTION"] if value["rules"]["FUZZ_EXCEPTION"] else []


def _fuzz_disable_rule(raw, rule_id):
    if rule_id != "FUZZ_EXCEPTION" or _deep_audit_io._fuzz_control_ids(raw) != [
        rule_id
    ]:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_CONTROL", "enabled exact fuzz rule required"
        )
    value = _deep_audit_io.strict_json(raw)
    value["rules"][rule_id] = False
    return _deep_audit_io.canonical_bytes(value)


def _fuzz_control_args(argv):
    path = _deep_audit_io.Path("/opt/factory/rules/fuzz-control.json")
    offset = 3
    if len(argv) < 3:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_CONTROL", "closed fuzz native arguments required"
        )
    if argv[2].startswith("--factory-control="):
        path = _deep_audit_io.Path(argv[2].removeprefix("--factory-control="))
        offset = 4
    if len(argv) < offset or argv[offset - 1] != "--":
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_CONTROL", "closed fuzz native arguments required"
        )
    with path.open("rb") as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_CONTROL", "fuzz config budget exceeded"
        )
    return (
        _deep_audit_io._fuzz_control_ids(raw),
        _deep_audit_io.sha256_bytes(raw),
        argv[offset:],
    )


def native_fuzz_main(argv: list[str]) -> int:
    """Image-owned Atheris lifecycle; candidate exports only TestOneInput(bytes)."""
    import atheris
    import coverage
    import importlib.util
    import sys

    harness_path, output = _deep_audit_io.Path(argv[0]), _deep_audit_io.Path(argv[1])
    contract = _deep_audit_io.strict_json(
        _deep_audit_io.Path("/factory-contract.json").read_bytes()
    )
    root = _deep_audit_io.Path.cwd()
    contract = _deep_audit_io._fuzz_execution_contract(contract, root)
    harness = harness_path.relative_to(root).as_posix()
    sources = {item["path"]: item["sha256"] for item in contract["inventory"]["files"]}
    _deep_audit_io.bound_bytes(root, {"path": harness, "sha256": sources[harness]})
    rule_ids, control_sha, native_args = _deep_audit_io._fuzz_control_args(argv)
    cov = coverage.Coverage(branch=True, data_file=None, source=[str(root)])
    cov.start()
    sys.dont_write_bytecode = True
    with atheris.instrument_imports():
        spec = importlib.util.spec_from_file_location(
            "factory_fuzz_target", harness_path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    target = module.TestOneInput
    state = {
        "executions": 0,
        "inputs": set(),
        "findings": [],
        "completed": False,
        "control_sha256": control_sha,
    }

    def callback(data):
        try:
            _deep_audit_io._fuzz_record_input(state, data)
        except _deep_audit_io.RuntimeAuditError:
            _deep_audit_io._fuzz_snapshot(cov, contract, harness, output, state)
            raise
        try:
            target(data)
        except Exception:
            if "FUZZ_EXCEPTION" in rule_ids:
                state["completed"] = True
                state["findings"].append(
                    {
                        "rule_id": "FUZZ_EXCEPTION",
                        "path": harness,
                        "line": 1,
                        "severity": "high",
                        "input_sha256": _deep_audit_io.sha256_bytes(data),
                    }
                )
                _deep_audit_io._fuzz_snapshot(cov, contract, harness, output, state)
                raise
        if state["executions"] == 1 or state["executions"] % 64 == 0:
            _deep_audit_io._fuzz_snapshot(cov, contract, harness, output, state)

    atheris.Setup([sys.argv[0], *native_args], atheris.instrument_func(callback))
    atheris.Fuzz()
    state["completed"] = True
    _deep_audit_io._fuzz_snapshot(cov, contract, harness, output, state)
    return 0


def _atheris_obligations(contract, lane):
    return [
        item
        for item in contract["obligations"]
        if item["engine"] == "atheris" and item["family"] == lane["family"]
    ]


def _atheris_challenge_gaps(obligations, code):
    return _deep_audit_io._challenge_bundle(
        [],
        [
            _deep_audit_io._challenge_gap_record(item, challenge, code)
            for item in obligations
            for challenge in item["challenges"]
        ],
    )


def _atheris_challenge_command(profile):
    if profile.get("engine") != "atheris" or len(profile.get("commands", [])) != 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_PROFILE", "one pinned Atheris command required"
        )
    command = profile["commands"][0]
    argv = list(command.get("argv", []))
    prefix = [
        "/usr/local/bin/python",
        "-I",
        "-m",
        "factoryline.deep_audit_io",
        "native-fuzz",
        "{fixture}",
        "{report}",
        "--factory-control={config}",
        "--",
    ]
    if (
        argv[: len(prefix)] != prefix
        or argv[len(prefix) :] != ["-runs=1000", "-artifact_prefix={scratch}/"]
        or command.get("accepted_exit_codes") != [0, 77]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_PROFILE", "pinned Atheris argv differs"
        )
    return {"argv": argv, "accepted_exit_codes": command["accepted_exit_codes"]}


def _atheris_challenges(profile, contract, source, lane, execution, started):
    from .runtime_audit_process import run_bounded_command

    obligations = _deep_audit_io._atheris_obligations(contract, lane)
    if (
        len(obligations) > 64
        or sum(len(item["challenges"]) for item in obligations) > 192
    ):
        return _deep_audit_io._atheris_challenge_gaps(
            obligations, "E_FUZZ_CHALLENGE_BUDGET"
        ), []
    if not obligations:
        return _deep_audit_io._challenge_bundle([], []), []
    try:
        baseline_path = _deep_audit_io.local_file(
            _deep_audit_io.Path("/opt/factory/rules"), "fuzz-control.json"
        )
        baseline = baseline_path.read_bytes()
        if (
            lane.get("rule_ids") != ["FUZZ_EXCEPTION"]
            or lane.get("ruleset_sha256") != profile.get("ruleset_sha256")
            or _deep_audit_io.sha256_bytes(baseline) != lane["ruleset_sha256"]
            or _deep_audit_io._fuzz_control_ids(baseline) != ["FUZZ_EXCEPTION"]
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_FUZZ_CONTROL", "signed fuzz baseline differs"
            )
        command = _deep_audit_io._atheris_challenge_command(profile)
    except (
        OSError,
        _deep_audit_io.RuntimeAuditError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        return _deep_audit_io._atheris_challenge_gaps(
            obligations, _deep_audit_io._challenge_error_code(exc)
        ), []

    observations, gaps = [], []
    deadline = started + lane["timeout_seconds"]
    with _deep_audit_io.tempfile.TemporaryDirectory(
        prefix="factory-atheris-challenges-"
    ) as root:
        for index, obligation in enumerate(obligations):
            for challenge in obligation["challenges"]:
                _deep_audit_io._atheris_challenge_control(
                    run_bounded_command,
                    profile,
                    contract,
                    source,
                    lane,
                    execution,
                    command,
                    baseline_path,
                    baseline,
                    obligation,
                    challenge,
                    _deep_audit_io.Path(root) / f"control-{index}-{challenge['kind']}",
                    deadline,
                    observations,
                    gaps,
                )
    return _deep_audit_io._challenge_bundle(observations, gaps), []


def _atheris_challenge_control(
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    baseline_path,
    baseline,
    obligation,
    challenge,
    case,
    deadline,
    observations,
    gaps,
):
    expected_exit = {"positive": 77, "negative": 0, "mutation": 0}.get(
        challenge.get("kind")
    )
    if expected_exit is None or challenge.get("expected_exit_code") != expected_exit:
        gaps.append(
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, "E_FUZZ_PROFILE"
            )
        )
        return
    if expected_exit not in command["accepted_exit_codes"]:
        gaps.append(
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, "E_FUZZ_PROFILE"
            )
        )
        return
    try:
        observation = _deep_audit_io._run_atheris_challenge(
            _deep_audit_io._native_challenge_executor(),
            runner,
            profile,
            contract,
            source,
            lane,
            execution,
            command,
            baseline_path,
            baseline,
            obligation,
            challenge,
            case,
            deadline,
        )
        observations.append(observation)
        try:
            _deep_audit_io._atheris_challenge_retained_budget(observations)
        except _deep_audit_io.RuntimeAuditError:
            observations.pop()
            raise
        if observation.get("execution", {}).get("status") != "VERIFIED":
            gaps.append(
                _deep_audit_io._challenge_gap_record(
                    obligation, challenge, "E_FUZZ_CHALLENGE_EXECUTION"
                )
            )
        gaps.append(
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, "FUZZ_CHALLENGE_REPLAY_REQUIRED"
            )
        )
    except (
        OSError,
        _deep_audit_io.RuntimeAuditError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        gaps.append(
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, _deep_audit_io._challenge_error_code(exc)
            )
        )


def _run_atheris_challenge(
    execute,
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    baseline_path,
    baseline,
    obligation,
    challenge,
    case,
    deadline,
):
    manifest = challenge.get("fixture_manifest")
    if not isinstance(manifest, dict) or not manifest:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CHALLENGE_MANIFEST", "signed fixture manifest required"
        )
    manifest = dict(sorted(manifest.items()))
    _deep_audit_io._semgrep_fixture_binding(
        manifest, obligation, source, challenge["fixture_path"]
    )
    case.mkdir()
    challenge_root = case / "source"
    for path, source_sha in manifest.items():
        target = challenge_root.joinpath(*_deep_audit_io.relative_path(path).split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(
            _deep_audit_io.bound_bytes(source, {"path": path, "sha256": source_sha})
        )
    challenge_sha = _deep_audit_io.digest(manifest)
    config_path = baseline_path
    if challenge["kind"] == "mutation":
        config_path = case / "fuzz-control.json"
        config_path.write_bytes(
            _deep_audit_io._fuzz_disable_rule(baseline, obligation["detector_rule_id"])
        )
    scratch = case / "run"
    report_path = scratch / "report.json"
    corpus_path = report_path.with_suffix(".corpus.json")
    ledger_path = scratch / "unused-ledger.json"
    bindings = {
        "source": str(challenge_root),
        "output": str(scratch),
        "report": str(report_path),
        "scratch": str(scratch),
        "candidate_sha256": challenge_sha,
        "factory_ledger": str(ledger_path),
        "config": str(config_path),
        "fixture": str(challenge_root / challenge["fixture_path"]),
    }
    retained = {}

    def report_parser(raw):
        with _deep_audit_io.local_file(scratch, corpus_path.name).open("rb") as stream:
            corpus_raw = stream.read(_deep_audit_io.LIMIT + 1)
        if len(corpus_raw) > _deep_audit_io.LIMIT:
            raise _deep_audit_io.RuntimeAuditError(
                "E_FUZZ_CORPUS", "retained corpus exceeds budget"
            )
        with _deep_audit_io.local_file(config_path.parent, config_path.name).open(
            "rb"
        ) as stream:
            effective = stream.read(4097)
        if len(effective) > 4096:
            raise _deep_audit_io.RuntimeAuditError(
                "E_FUZZ_CONTROL", "control config exceeds budget"
            )
        normalized = _deep_audit_io._atheris_challenge_report(
            raw, corpus_raw, effective, challenge, lane, manifest
        )
        retained.update(
            {
                "schema": "factory.atheris-retained-challenge.v1",
                "source_manifest": manifest,
                "source_manifest_sha256": _deep_audit_io.digest(manifest),
                "raw_report": _deep_audit_io._codeql_native_blob(
                    raw, _deep_audit_io.LIMIT
                ),
                "corpus_manifest": _deep_audit_io._codeql_native_blob(
                    corpus_raw, _deep_audit_io.LIMIT
                ),
                "effective_config": _deep_audit_io._codeql_native_blob(effective, 4096),
            }
        )
        return normalized

    timeout = int(deadline - _deep_audit_io.time.monotonic())
    if timeout < 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "shared challenge deadline expired"
        )
    observation = execute(
        challenge,
        obligation_id=obligation["id"],
        engine="atheris",
        detector_rule_id=obligation["detector_rule_id"],
        detector_enabled=challenge["kind"] != "mutation",
        profile_argv=command["argv"],
        bindings=bindings,
        source_root=challenge_root,
        baseline_config_path=baseline_path,
        effective_config_path=config_path,
        report_path=report_path,
        ledger_path=ledger_path,
        scratch=scratch,
        scratch_parent=case,
        timeout_seconds=timeout,
        expected_ruleset_sha256=lane["ruleset_sha256"],
        execution_bindings={
            "candidate_sha256": contract["inventory"]["candidate_sha256"],
            "challenge_source_sha256": challenge_sha,
            "profile_sha256": _deep_audit_io.digest(profile),
            "image_sha256": _deep_audit_io.sha256_bytes(lane["image"].encode("utf-8")),
            "tool_version": profile["tool_version"],
            "version_probe_sha256": _deep_audit_io.digest(execution["version_probe"]),
            "version_probe_facts": execution["version_probe"],
        },
        runner=runner,
        report_parser=report_parser,
        config_rule_ids=_deep_audit_io._fuzz_control_ids,
        verify_mutation=lambda old, new, rule: _deep_audit_io._fuzz_disable_rule(
            old, rule
        )
        == new,
        native_artifact_roles=lane["native_artifact_roles"],
        native_artifacts={"fuzz_result": report_path, "corpus_manifest": corpus_path},
        rule_ids=lane["rule_ids"],
        mutation_ruleset_sha256=lane["mutation_config_sha256"],
    )
    observation["atheris_native_evidence"] = retained
    _deep_audit_io._osv_check_deadline(deadline)
    return observation


def _atheris_challenge_report(
    raw, corpus_raw, effective_config, challenge, lane, manifest
):
    report = _deep_audit_io.strict_json(raw)
    if (
        _deep_audit_io.canonical_bytes(report) != raw
        or report.get("schema") != "factory.deep-atheris-observations.v1"
        or report.get("engine") != "atheris"
        or report.get("tool_version") != lane["tool_version"]
        or type(report.get("completed")) is not bool
        or (challenge["kind"] == "positive" and report["completed"] is not True)
        or report.get("errors") != []
        or report.get("control_sha256") != _deep_audit_io.sha256_bytes(effective_config)
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPORT", "native control report differs"
        )
    harness_path = challenge["fixture_path"]
    harness = {"path": harness_path, "sha256": manifest[harness_path]}
    sources = dict(manifest)
    if report.get("harness") != harness:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPORT", "native harness binding differs"
        )
    corpus = _deep_audit_io._validate_fuzz_corpus(corpus_raw, report, sources)
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPORT", "native findings list required"
        )
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or set(finding) != {"rule_id", "path", "line", "severity", "input_sha256"}
            or finding.get("rule_id") != "FUZZ_EXCEPTION"
            or finding.get("path") != harness_path
            or type(finding.get("line")) is not int
            or finding.get("line") != 1
            or finding.get("severity") != "high"
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_FUZZ_REPORT", "unknown or unbound fuzz finding"
            )
        input_sha = _deep_audit_io.require_digest(
            finding.get("input_sha256"), "input_sha256"
        )
        if input_sha not in {item["sha256"] for item in corpus["inputs"]}:
            raise _deep_audit_io.RuntimeAuditError(
                "E_FUZZ_REPORT", "finding input is not retained"
            )
    expected_count = 1 if challenge["kind"] == "positive" else 0
    if len(findings) != expected_count:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_REPORT", "fuzz control semantics differ"
        )
    if _deep_audit_io._fuzz_control_ids(effective_config) != (
        ["FUZZ_EXCEPTION"] if challenge["kind"] != "mutation" else []
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_CONTROL", "effective detector state differs"
        )
    normalized_findings = (
        [{"rule_id": "FUZZ_EXCEPTION", "path": harness_path, "severity": "high"}]
        if findings
        else []
    )
    return {
        "schema": "factory.atheris-challenge-observation.v1",
        "kind": challenge["kind"],
        "control_sha256": _deep_audit_io.sha256_bytes(effective_config),
        "harness": harness,
        "findings": normalized_findings,
    }


def _fuzz_fixture_manifest_binding(manifest, obligation, sources, fixture_path):
    paths = set(obligation["paths"])
    if (
        not isinstance(manifest, dict)
        or not manifest
        or fixture_path not in paths
        or fixture_path not in manifest
        or not set(manifest) <= paths
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CHALLENGE_BINDING", "fixture manifest differs"
        )
    for path, source_sha in manifest.items():
        _deep_audit_io.relative_path(path)
        _deep_audit_io.require_digest(source_sha, "fixture_sha256")
        if sources.get(path) != source_sha:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CHALLENGE_BINDING", "fixture source differs"
            )


def _osv_check_deadline(deadline):
    if deadline is not None and _deep_audit_io.time.monotonic() >= deadline:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "shared challenge deadline expired"
        )


def _osv_challenges(profile, contract, source, lane, execution, started):
    from .runtime_audit_process import run_bounded_command

    obligations = _deep_audit_io._osv_obligations(contract, lane)
    observations, gaps, covered = [], [], []
    deadline = started + lane["timeout_seconds"]
    if len(obligations) > 64:
        return _deep_audit_io._osv_challenge_gaps(
            obligations, "E_OSV_CHALLENGE_BUDGET"
        ), []
    if not obligations:
        return _deep_audit_io._challenge_bundle(observations, gaps), covered
    try:
        baseline_path = _deep_audit_io.local_file(
            _deep_audit_io.Path("/opt/factory/rules"), "osv-scanner.toml"
        )
        baseline = baseline_path.read_bytes()
        _deep_audit_io._osv_policy_inputs(profile, baseline)
        policy = lane["native_policy"]
        if _deep_audit_io.sha256_bytes(baseline) != policy["baseline_config_sha256"]:
            raise _deep_audit_io.RuntimeAuditError(
                "E_OSV_POLICY", "signed baseline hash differs"
            )
        _deep_audit_io._osv_database_identity(lane, deadline)
        command = _deep_audit_io._osv_challenge_command(profile)
    except (
        OSError,
        _deep_audit_io.RuntimeAuditError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        return _deep_audit_io._osv_challenge_gaps(
            obligations, _deep_audit_io._challenge_error_code(exc)
        ), []
    with _deep_audit_io.tempfile.TemporaryDirectory(
        prefix="factory-osv-challenges-"
    ) as root:
        for index, obligation in enumerate(obligations):
            results = {}
            for challenge in obligation["challenges"]:
                _deep_audit_io._osv_challenge_control(
                    run_bounded_command,
                    profile,
                    contract,
                    source,
                    lane,
                    execution,
                    command,
                    baseline_path,
                    baseline,
                    obligation,
                    challenge,
                    _deep_audit_io.Path(root) / f"control-{index}-{challenge['kind']}",
                    deadline,
                    observations,
                    gaps,
                    results,
                )
            if _deep_audit_io._osv_challenge_controls_match(results):
                covered.append(obligation["id"])
            else:
                for challenge in obligation["challenges"]:
                    if (obligation["id"], challenge["kind"]) not in {
                        (item.get("obligation_id"), item.get("kind")) for item in gaps
                    }:
                        gaps.append(
                            _deep_audit_io._challenge_gap_record(
                                obligation, challenge, "E_OSV_CHALLENGE_BINDING"
                            )
                        )
    return _deep_audit_io._challenge_bundle(observations, gaps), covered


def _osv_obligations(contract, lane):
    return [
        item
        for item in contract["obligations"]
        if item["engine"] == "osv" and item["family"] == lane["family"]
    ]


def _osv_challenge_gaps(obligations, code):
    gaps = [
        _deep_audit_io._challenge_gap_record(item, challenge, code)
        for item in obligations
        for challenge in item["challenges"]
    ]
    return _deep_audit_io._challenge_bundle([], gaps)


def _osv_challenge_command(profile):
    if profile.get("engine") != "osv" or len(profile.get("commands", [])) != 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_PROFILE", "one pinned OSV command required"
        )
    argv = list(profile["commands"][0].get("argv", []))
    try:
        if argv[argv.index("--config") + 1] != "/opt/factory/rules/osv-scanner.toml":
            raise ValueError
        argv[argv.index("--config") + 1] = "{config}"
        if argv[argv.index("-r") + 1] != "{source}" or argv[-1] != "{report}":
            raise ValueError
    except (ValueError, IndexError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_PROFILE", "pinned OSV argv differs"
        ) from exc
    return {
        "argv": argv,
        "accepted_exit_codes": profile["commands"][0]["accepted_exit_codes"],
    }


def _osv_challenge_controls_match(results):
    if {"positive", "negative", "mutation"} != set(results):
        return False
    positive, mutation = results["positive"], results["mutation"]
    return (
        positive["inventory"] == mutation["inventory"]
        and positive["unrelated_rows"] == mutation["unrelated_rows"]
        and bool(positive["target_rows"])
        and not mutation["target_rows"]
    )


def _osv_challenge_control(
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    baseline_path,
    baseline,
    obligation,
    challenge,
    case,
    deadline,
    observations,
    gaps,
    results,
):
    remaining = int(deadline - _deep_audit_io.time.monotonic())
    if remaining < 1:
        gaps.append(
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, "E_ADAPTER_TIMEOUT"
            )
        )
        return
    if challenge.get("expected_exit_code") not in command["accepted_exit_codes"]:
        gaps.append(
            _deep_audit_io._challenge_gap_record(obligation, challenge, "E_OSV_PROFILE")
        )
        return
    try:
        observation, summary = _deep_audit_io._run_osv_challenge(
            _deep_audit_io._native_challenge_executor(),
            runner,
            profile,
            contract,
            source,
            lane,
            execution,
            command,
            baseline_path,
            baseline,
            obligation,
            challenge,
            case,
            deadline,
            remaining,
        )
        observations.append(observation)
        if observation.get("execution", {}).get("status") == "VERIFIED":
            try:
                _deep_audit_io._osv_challenge_retained_budget(observations)
            except _deep_audit_io.RuntimeAuditError:
                observations.pop()
                raise
            results[challenge["kind"]] = summary
        else:
            gaps.append(
                _deep_audit_io._challenge_gap_record(
                    obligation, challenge, "E_OSV_CHALLENGE_EXECUTION"
                )
            )
    except (
        OSError,
        _deep_audit_io.RuntimeAuditError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        gaps.append(
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, _deep_audit_io._challenge_error_code(exc)
            )
        )


def _run_osv_challenge(
    execute,
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    baseline_path,
    baseline,
    obligation,
    challenge,
    case,
    deadline,
    timeout,
):
    manifest = dict(sorted(challenge["fixture_manifest"].items()))
    _deep_audit_io._semgrep_fixture_binding(
        manifest, obligation, source, challenge["fixture_path"]
    )
    case.mkdir()
    challenge_root = case / "source"
    for path, source_sha in manifest.items():
        target = challenge_root.joinpath(*_deep_audit_io.relative_path(path).split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(
            _deep_audit_io.bound_bytes(source, {"path": path, "sha256": source_sha})
        )
    challenge_sha = _deep_audit_io.digest(manifest)
    config_path = baseline_path
    if challenge["kind"] == "mutation":
        config_path = _deep_audit_io._osv_mutation_path(
            case, baseline, lane, obligation
        )
    scratch = case / "run"
    report_path, database_path = (
        scratch / "report.json",
        scratch / "database-identity.json",
    )
    ledger_path = scratch / "unused-ledger.json"
    bindings = _deep_audit_io._native_challenge_bindings(
        challenge_root, scratch, report_path, ledger_path, config_path, challenge_sha
    )
    summary = {}
    retained = {}

    def report_parser(raw):
        report = _deep_audit_io._osv_parse_challenge_report(
            raw, challenge_root, manifest, lane, obligation, challenge
        )
        from .deep_audit_sarif import _osv_challenge_rows

        summary.update(
            _osv_challenge_rows(report, lane, manifest, obligation, challenge["kind"])
        )
        try:
            retained.update(
                {
                    "schema": "factory.osv-retained-challenge.v1",
                    "source_root": challenge_root.as_posix(),
                    "source_manifest": manifest,
                    "source_manifest_sha256": _deep_audit_io.digest(manifest),
                    "raw_report": _deep_audit_io._osv_native_blob(raw),
                    "effective_config": _deep_audit_io._osv_native_blob(
                        config_path.read_bytes()
                    ),
                    "database_identity": _deep_audit_io._osv_native_blob(
                        database_path.read_bytes()
                    ),
                }
            )
        except OSError as exc:
            raise _deep_audit_io.RuntimeAuditError(
                "E_OSV_ARTIFACT", "challenge native artifacts unavailable"
            ) from exc
        return report

    def challenge_runner(argv, cwd, budget, run_scratch):
        return _deep_audit_io._osv_challenge_runner(
            runner, argv, cwd, budget, run_scratch, database_path, lane, deadline
        )

    timeout = int(deadline - _deep_audit_io.time.monotonic())
    if timeout < 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "shared challenge deadline expired"
        )

    observation = execute(
        challenge,
        obligation_id=obligation["id"],
        engine="osv",
        detector_rule_id=obligation["detector_rule_id"],
        detector_enabled=challenge["kind"] != "mutation",
        profile_argv=command["argv"],
        bindings=bindings,
        source_root=challenge_root,
        baseline_config_path=baseline_path,
        effective_config_path=config_path,
        report_path=report_path,
        ledger_path=ledger_path,
        scratch=scratch,
        scratch_parent=case,
        timeout_seconds=timeout,
        expected_ruleset_sha256=lane["native_policy"]["baseline_config_sha256"],
        execution_bindings=_deep_audit_io._osv_execution_bindings(
            profile, contract, lane, execution, challenge_sha
        ),
        runner=challenge_runner,
        report_parser=report_parser,
        config_rule_ids=lambda raw: _deep_audit_io._osv_config_rule_ids(raw, lane),
        verify_mutation=lambda original,
        effective,
        rule: _deep_audit_io._osv_mutation_valid(original, effective, rule, lane),
        native_artifact_roles=lane["native_artifact_roles"],
        native_artifacts={
            "osv_json_report": report_path,
            "advisory_db_identity": database_path,
        },
        rule_ids=lane["rule_ids"],
        mutation_ruleset_sha256=lane["mutation_config_sha256"],
    )
    observation["osv_control_evidence"] = summary
    observation["osv_native_evidence"] = retained
    return observation, summary


def _native_challenge_bindings(source, scratch, report, ledger, config, candidate_sha):
    return {
        "source": str(source),
        "output": str(scratch),
        "report": str(report),
        "scratch": str(scratch),
        "candidate_sha256": candidate_sha,
        "factory_ledger": str(ledger),
        "config": str(config),
    }


def _osv_execution_bindings(profile, contract, lane, execution, challenge_sha):
    from .runtime_audit_common import sha256_bytes as common_sha256

    version_probe = execution["version_probe"]
    image = _deep_audit_io.require_str(lane.get("image"), "image", maximum=512)
    return {
        "candidate_sha256": contract["inventory"]["candidate_sha256"],
        "challenge_source_sha256": challenge_sha,
        "profile_sha256": _deep_audit_io.digest(profile),
        "image_sha256": common_sha256(image.encode("utf-8")),
        "tool_version": profile["tool_version"],
        "version_probe_sha256": _deep_audit_io.digest(version_probe),
        "version_probe_facts": version_probe,
    }


def _osv_parse_challenge_report(
    raw, source_root, manifest, lane, obligation, challenge
):
    report = _deep_audit_io.strict_json(raw)
    if not isinstance(report, dict):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_REPORT", "native OSV report object required"
        )
    _deep_audit_io._osv_challenge_source_paths(report, source_root, manifest)
    return report


def _osv_mutation_path(case, baseline, lane, obligation):
    rule = obligation["detector_rule_id"]
    aliases = lane["native_policy"]["advisory_aliases"][rule]
    effective = _deep_audit_io._osv_suppression_bytes(aliases)
    if _deep_audit_io.sha256_bytes(effective) != lane["mutation_config_sha256"][rule]:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_MUTATION_BINDING", "signed suppression digest differs"
        )
    path = case / "mutation-osv-scanner.toml"
    path.write_bytes(effective)
    return path


def _osv_challenge_runner(
    runner, argv, cwd, budget, scratch, database_path, lane, deadline
):
    expected = _deep_audit_io._osv_database_identity(lane, deadline)
    identity = _deep_audit_io.canonical_bytes(expected)
    database_path.write_bytes(identity)
    remaining = int(deadline - _deep_audit_io.time.monotonic())
    if remaining < 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "shared challenge deadline expired"
        )
    cancelled = _deep_audit_io.threading.Event()
    timer = _deep_audit_io.threading.Timer(remaining, cancelled.set)
    timer.daemon = True
    timer.start()
    try:
        facts = runner(argv, cwd, budget, scratch, cancelled=cancelled)
    finally:
        timer.cancel()
    if _deep_audit_io._osv_database_identity(lane, deadline) != expected:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_DATABASE", "database identity drifted during scan"
        )
    if _deep_audit_io.time.monotonic() >= deadline:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "shared challenge deadline expired"
        )
    return facts


def _osv_challenge_manifest(evidence, bound, kind):
    _deep_audit_io.exact_keys(
        evidence,
        {
            "schema",
            "source_root",
            "source_manifest",
            "source_manifest_sha256",
            "raw_report",
            "effective_config",
            "database_identity",
        },
    )
    manifest = evidence["source_manifest"]
    if (
        evidence["schema"] != "factory.osv-retained-challenge.v1"
        or not isinstance(manifest, dict)
        or evidence["source_manifest_sha256"] != _deep_audit_io.digest(manifest)
        or manifest != bound["fixture_manifest"]
        or kind not in {"positive", "negative", "mutation"}
    ):
        raise ValueError("challenge evidence binding differs")
    return manifest


def _osv_challenge_execution(observation, lane, manifest):
    execution = observation["execution"]
    if (
        execution.get("status") != "VERIFIED"
        or execution.get("baseline_config_sha256")
        != lane["native_policy"]["baseline_config_sha256"]
        or execution.get("challenge_source_sha256") != _deep_audit_io.digest(manifest)
        or observation.get("observation_sha256")
        != _deep_audit_io.digest(observation["report"])
    ):
        raise ValueError("challenge execution binding differs")


def _osv_challenge_report_bytes(evidence, lane, observation, obligation, kind):
    execution = observation["execution"]
    raw = _deep_audit_io._osv_native_bytes(evidence["raw_report"])
    policy = _deep_audit_io._osv_native_bytes(evidence["effective_config"])
    _deep_audit_io._osv_database_artifact(evidence["database_identity"], lane)
    expected = _deep_audit_io._osv_expected_policy(lane, obligation, kind)
    if (
        policy != expected
        or _deep_audit_io.sha256_bytes(policy) != execution["effective_config_sha256"]
        or execution["raw_report_sha256"] != _deep_audit_io.sha256_bytes(raw)
        or not _deep_audit_io._osv_challenge_artifacts_valid(
            execution["native_artifacts"], lane["native_artifact_roles"], raw, evidence
        )
    ):
        raise ValueError("challenge artifact binding differs")
    return raw


def _osv_challenge_artifacts_valid(records, roles, raw, evidence):
    if not isinstance(records, list) or len(records) != 2:
        return False
    by_role = {}
    total = 0
    for record in records:
        try:
            _deep_audit_io.exact_keys(record, {"kind", "sha256", "bytes"})
            role = _deep_audit_io.require_str(
                record["kind"], "artifact kind", maximum=64
            )
            _deep_audit_io.require_digest(record["sha256"], "artifact hash")
            size = _deep_audit_io.require_int(
                record["bytes"], "artifact bytes", minimum=0, maximum=8 * 1024 * 1024
            )
            if role in by_role:
                return False
            by_role[role] = record
            total += size
        except (_deep_audit_io.RuntimeAuditError, TypeError, KeyError):
            return False
    database = _deep_audit_io._osv_native_bytes(evidence["database_identity"])
    expected = {"osv_json_report": raw, "advisory_db_identity": database}
    return (
        set(by_role) == set(roles) == set(expected)
        and all(
            by_role[role]["sha256"] == _deep_audit_io.sha256_bytes(data)
            and by_role[role]["bytes"] == len(data)
            for role, data in expected.items()
        )
        and total <= 8 * 1024 * 1024
    )


def execute_osv_native_replay(request, source, scratch, timeout):
    """Independently rerun the pinned offline scanner and every signed OSV control."""
    _deep_audit_io.exact_keys(
        request,
        {"lane", "inventory", "coverage", "report", "challenges", "obligations"},
    )
    lane, inventory, coverage = (
        request["lane"],
        request["inventory"],
        request["coverage"],
    )
    started = _deep_audit_io.time.monotonic()
    timeout = _deep_audit_io.require_int(
        timeout, "OSV replay timeout", minimum=1, maximum=3600
    )
    deadline = started + timeout
    profile = _deep_audit_io.strict_json(
        _deep_audit_io.Path("/opt/factory/adapter-profile.json").read_bytes()
    )
    _deep_audit_io._native_profile(profile, lane)
    if (
        coverage.get("profile_sha256") != _deep_audit_io.digest(profile)
        or coverage.get("image_binding_sha256")
        != _deep_audit_io.sha256_bytes(str(lane.get("image", "")).encode("utf-8"))
        or coverage.get("tool_version") != profile["tool_version"]
        or coverage.get("ruleset_sha256") != profile["ruleset_sha256"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_REPLAY", "pinned profile binding differs"
        )
    _deep_audit_io._adapter_sources(source, inventory)
    required = {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }
    _deep_audit_io.verify_osv_retained_evidence(
        coverage,
        lane,
        required,
        request["report"],
        request["challenges"],
        request["obligations"],
    )
    fresh, report, findings, accounting = _deep_audit_io._osv_replay_primary(
        request, profile, source, scratch, lane, inventory, required, deadline
    )
    controls = _deep_audit_io._osv_replay_controls(
        request, profile, source, lane, fresh, report, required, deadline
    )
    _deep_audit_io._adapter_sources(source, inventory)
    expected_controls = _deep_audit_io._osv_replay_control_ids(
        request["obligations"], lane, required
    )
    return {
        "schema": "factory.osv-native-replay.v1",
        "state": "VERIFIED",
        "candidate_sha256": inventory["candidate_sha256"],
        "lane_sha256": _deep_audit_io.digest(lane),
        "coverage_sha256": _deep_audit_io.digest(coverage),
        "report_sha256": _deep_audit_io.digest(request["report"]),
        "challenges_sha256": _deep_audit_io.digest(request["challenges"]),
        "obligations_sha256": _deep_audit_io.digest(request["obligations"]),
        "profile_sha256": coverage["profile_sha256"],
        "database_sha256": lane["native_policy"]["database_sha256"],
        "source_paths": sorted(required),
        "controls": expected_controls,
        "findings_sha256": _deep_audit_io.digest(findings),
        "source_accounting_sha256": _deep_audit_io.digest(accounting),
        "native_execution_sha256": _deep_audit_io.digest(
            {"primary": fresh["invocations"], "controls": controls}
        ),
    }


def _osv_replay_primary(
    request, profile, source, scratch, lane, inventory, required, deadline
):
    from .deep_audit_sarif import _native_execution_report, _osv_source_accounting

    coverage = request["coverage"]
    _deep_audit_io._osv_database_identity(lane, deadline)
    replay_lane = {
        **lane,
        "timeout_seconds": min(
            lane["timeout_seconds"], _deep_audit_io._osv_replay_remaining(deadline)
        ),
    }
    output = _deep_audit_io.Path(scratch) / "osv-primary"
    output.mkdir(parents=True, exist_ok=False)
    paths = _deep_audit_io._adapter_output_paths(
        replay_lane, output, create_parents=True
    )
    replay_lane = {
        **lane,
        "timeout_seconds": min(
            lane["timeout_seconds"], _deep_audit_io._osv_replay_remaining(deadline)
        ),
    }
    contract = {
        "inventory": inventory,
        "lane": replay_lane,
        "obligations": request["obligations"],
    }
    fresh = _deep_audit_io._run_native_profile(
        profile, contract, source, output, inventory, replay_lane, paths
    )
    _deep_audit_io._osv_check_deadline(deadline)
    report = _deep_audit_io._native_report(
        fresh["raw_report"], profile, contract, output, fresh["invocations"]
    )
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    findings = _native_execution_report(report, lane, sources)
    expected_findings = _native_execution_report(request["report"], lane, sources)
    if sorted(findings, key=_deep_audit_io.canonical_bytes) != sorted(
        expected_findings, key=_deep_audit_io.canonical_bytes
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_REPLAY", "independent findings differ"
        )
    accounting = _osv_source_accounting(report, required, lane["mode"])
    if accounting["state"] != "COMPLETE" or accounting != coverage["source_accounting"]:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_REPLAY", "independent source accounting differs"
        )
    return fresh, report, findings, accounting


def _osv_replay_controls(
    request, profile, source, lane, fresh, report, required, deadline
):
    control_timeout = min(
        lane["timeout_seconds"], _deep_audit_io._osv_replay_remaining(deadline)
    )
    replay_lane = {**lane, "timeout_seconds": control_timeout}
    replay_contract = {
        "inventory": request["inventory"],
        "lane": replay_lane,
        "obligations": request["obligations"],
    }
    replay_execution = {**fresh, "raw_report": report}
    fresh_challenges, covered = _deep_audit_io._native_profile_challenges(
        profile,
        replay_contract,
        source,
        replay_lane,
        replay_execution,
        deadline - control_timeout,
    )
    _deep_audit_io._osv_check_deadline(deadline)
    controls = _deep_audit_io._osv_replay_compare_controls(
        request["challenges"], fresh_challenges, request["obligations"], lane, required
    )
    expected_obligation_ids = {
        item["id"]
        for item in request["obligations"]
        if item["engine"] == "osv"
        and item["family"] == lane["family"]
        and set(item["paths"]) <= set(required)
    }
    if set(covered) != expected_obligation_ids:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_REPLAY", "independent controls incomplete"
        )
    return controls


def _osv_replay_remaining(deadline):
    remaining = int(deadline - _deep_audit_io.time.monotonic())
    if remaining < 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_REPLAY", "shared replay deadline expired"
        )
    return remaining


def _osv_replay_control_ids(obligations, lane, required):
    rows = [
        {"id": item["id"], "kind": challenge["kind"]}
        for item in obligations
        if item["engine"] == "osv"
        and item["family"] == lane["family"]
        and set(item["paths"]) <= set(required)
        for challenge in item["challenges"]
    ]
    rows.sort(key=lambda item: (item["id"], item["kind"]))
    if (
        not rows
        or len(rows) > 192
        or len({(r["id"], r["kind"]) for r in rows}) != len(rows)
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_REPLAY", "complete bounded control identities required"
        )
    return rows


def _osv_replay_compare_controls(expected, actual, obligations, lane, required):
    identities = _deep_audit_io._osv_replay_identities(obligations, lane, required)
    expected_rows = _deep_audit_io._osv_replay_row_map(expected)
    actual_rows = _deep_audit_io._osv_replay_row_map(actual)
    if (
        expected.get("gaps")
        or actual.get("gaps")
        or set(expected_rows) != identities
        or set(actual_rows) != identities
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_REPLAY", "challenge set or execution differs"
        )
    _deep_audit_io._osv_replay_semantics_match(expected_rows, actual_rows, identities)
    return _deep_audit_io._osv_replay_execution_facts(actual_rows)


def _osv_replay_identities(obligations, lane, required):
    return {
        (row["id"], challenge["kind"])
        for row in obligations
        if row["engine"] == "osv"
        and row["family"] == lane["family"]
        and set(row["paths"]) <= set(required)
        for challenge in row["challenges"]
    }


def _osv_replay_row_map(bundle):
    rows = bundle.get("observations", [])
    mapped = {}
    for row in rows:
        key = (row.get("obligation_id"), row.get("kind"))
        if key in mapped:
            raise _deep_audit_io.RuntimeAuditError(
                "E_OSV_REPLAY", "duplicate challenge observation"
            )
        mapped[key] = row
    return mapped


def _osv_replay_semantics_match(expected_rows, actual_rows, identities):
    results = {}
    for key in sorted(identities):
        old, new = expected_rows[key], actual_rows[key]
        old_execution, new_execution = old["execution"], new["execution"]
        if (
            old_execution.get("status") != "VERIFIED"
            or new_execution.get("status") != "VERIFIED"
            or old.get("osv_control_evidence") != new.get("osv_control_evidence")
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_OSV_REPLAY", "challenge evidence differs"
            )
        results.setdefault(key[0], {})[key[1]] = new["osv_control_evidence"]
    for controls in results.values():
        if not _deep_audit_io._osv_challenge_controls_match(controls):
            raise _deep_audit_io.RuntimeAuditError(
                "E_OSV_REPLAY", "challenge semantics differ"
            )


def _osv_replay_execution_facts(actual_rows):
    return {
        f"{key[0]}:{key[1]}": {
            "argv_sha256": actual_rows[key]["execution"]["argv_sha256"],
            "raw_report_sha256": actual_rows[key]["execution"]["raw_report_sha256"],
            "execution_sha256": actual_rows[key]["execution"]["execution_sha256"],
        }
        for key in sorted(actual_rows)
    }


def _osv_challenges_complete(challenges, covered_obligations):
    observations = challenges.get("observations", [])
    identities = {item.get("obligation_id") for item in observations}
    controls = {(item.get("obligation_id"), item.get("kind")) for item in observations}
    return (
        bool(identities)
        and not challenges.get("gaps")
        and controls
        == {
            (identity, kind)
            for identity in identities
            for kind in ("positive", "negative", "mutation")
        }
        and set(covered_obligations) == identities
        and len(covered_obligations) == len(identities)
        and all(
            item.get("execution", {}).get("status") == "VERIFIED"
            for item in observations
        )
    )


def execute_codeql_native_replay(request, source, scratch, timeout):
    """Rerun the pinned suite and compare native values, never worker verdicts."""
    from .deep_audit_sarif import _native_execution_report

    lane, inventory = request["lane"], request["inventory"]
    coverage = request["coverage"]
    profile = _deep_audit_io.strict_json(
        _deep_audit_io.Path("/opt/factory/adapter-profile.json").read_bytes()
    )
    _deep_audit_io._native_profile(profile, lane)
    _deep_audit_io._adapter_sources(source, inventory)
    required = {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }
    _deep_audit_io.verify_codeql_retained_evidence(coverage, lane, required)
    deadline = _deep_audit_io.time.monotonic() + _deep_audit_io.require_int(
        timeout, "replay timeout", minimum=1, maximum=3600
    )
    _deep_audit_io._native_version(
        profile, source, scratch, _deep_audit_io._codeql_replay_remaining(deadline)
    )
    selected = _deep_audit_io._codeql_query_preflight(
        profile, source, scratch, _deep_audit_io._codeql_replay_remaining(deadline)
    )
    _deep_audit_io._codeql_replay_selection(
        selected, coverage["codeql_query_inventory"]
    )
    fresh = _deep_audit_io._codeql_replay_fresh(
        profile, source, scratch, inventory, lane, deadline
    )
    decoded = _deep_audit_io._codeql_replay_queries(
        profile, coverage, fresh, source, scratch, deadline
    )
    _deep_audit_io._codeql_replay_source_values(
        profile, coverage, fresh, source, scratch, deadline
    )
    _deep_audit_io._codeql_replay_sources(
        coverage["codeql_source_execution"], fresh["source"], inventory, lane
    )
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    findings = _native_execution_report(fresh["report"], lane, sources)
    if sorted(findings, key=_deep_audit_io.canonical_bytes) != sorted(
        _native_execution_report(request["report"], lane, sources),
        key=_deep_audit_io.canonical_bytes,
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_REPLAY", "independent findings differ"
        )
    _deep_audit_io._adapter_sources(source, inventory)
    return {
        "schema": "factory.codeql-native-replay.v1",
        "state": "VERIFIED",
        "candidate_sha256": inventory["candidate_sha256"],
        "lane_sha256": _deep_audit_io.digest(lane),
        "coverage_sha256": _deep_audit_io.digest(coverage),
        "queries": len(decoded),
        "decoded_queries_sha256": _deep_audit_io.digest(decoded),
        "findings_sha256": _deep_audit_io.digest(findings),
        "source_paths": sorted(required),
        "native_execution_sha256": _deep_audit_io.digest(fresh["invocations"]),
    }


def _codeql_replay_remaining(deadline):
    remaining = int(deadline - _deep_audit_io.time.monotonic())
    if remaining < 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_REPLAY", "independent replay deadline exhausted"
        )
    return remaining


def _codeql_replay_selection(actual, expected):
    for field in (  # noqa: F402 - preserve original audited function body
        "queries",
        "query_ids",
        "suite_sha256",
        "query_inventory_sha256",
    ):
        if actual[field] != expected[field]:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_REPLAY", "independent query selection differs"
            )


def _codeql_replay_fresh(profile, source, scratch, inventory, lane, deadline):
    report = scratch / "replay.sarif"
    commands = _deep_audit_io._native_argv(
        profile["commands"], {"source": source, "scratch": scratch, "report": report}
    )
    _, invocations = _deep_audit_io._codeql_steps_runner(
        commands, source, _deep_audit_io._codeql_replay_remaining(deadline), scratch
    )
    selected = _deep_audit_io._codeql_query_preflight(
        profile, source, scratch, _deep_audit_io._codeql_replay_remaining(deadline)
    )
    execution = _deep_audit_io._codeql_query_execution(
        profile, selected, source, scratch, deadline
    )
    measured = _deep_audit_io._codeql_source_measurement(
        profile, source, scratch, inventory, lane, deadline
    )
    with _deep_audit_io.local_file(scratch, report.name).open("rb") as stream:
        native_report = _deep_audit_io.strict_json(
            stream.read(_deep_audit_io.LIMIT + 1)
        )
    native_report = _deep_audit_io._native_report(
        native_report,
        profile,
        {"inventory": inventory, "lane": lane},
        scratch,
        invocations,
    )
    return {
        "execution": execution,
        "source": measured,
        "report": native_report,
        "invocations": invocations,
    }


def _codeql_replay_queries(profile, coverage, fresh, source, scratch, deadline):
    expected = {
        row["rule_id"]: row for row in coverage["codeql_query_execution"]["rules"]
    }
    actual = {row["rule_id"]: row for row in fresh["execution"]["rules"]}
    if set(expected) != set(actual):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_REPLAY", "independent query records differ"
        )
    decoded, total = {}, 0
    for index, rule_id in enumerate(sorted(expected)):
        old, new = expected[rule_id], actual[rule_id]
        directory = scratch / f"replay-values-{index}"
        directory.mkdir()
        left = _deep_audit_io._codeql_replay_decode(
            profile, old, source, directory, "worker", deadline
        )
        right = _deep_audit_io._codeql_replay_decode(
            profile, new, source, directory, "fresh", deadline
        )
        if left != right:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_REPLAY", "independent query values differ"
            )
        total += len(_deep_audit_io.canonical_bytes(left)) + len(
            _deep_audit_io.canonical_bytes(right)
        )
        if total > 536_870_912:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_REPLAY", "decoded replay budget exceeded"
            )
        decoded[old["rule_id"]] = _deep_audit_io.digest(left)
    return decoded


def _codeql_replay_source_values(profile, coverage, fresh, source, scratch, deadline):
    directory = scratch / "replay-source-values"
    directory.mkdir()
    values = []
    for label, measurement in (
        ("worker", coverage["codeql_source_execution"]),
        ("fresh", fresh["source"]),
    ):
        record = {
            "native_artifacts": measurement["native_artifacts"],
            "result_sets": _deep_audit_io._codeql_result_sets(
                _deep_audit_io._codeql_blob_bytes(
                    measurement["native_artifacts"]["info"], 65_536
                )
            ),
        }
        values.append(
            _deep_audit_io._codeql_replay_decode(
                profile, record, source, directory, label, deadline
            )
        )
    if values[0] != values[1]:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_REPLAY", "independent source values differ"
        )


def _codeql_replay_decode(profile, record, source, directory, label, deadline):
    result = directory / (label + ".bqrs")
    result.write_bytes(
        _deep_audit_io._codeql_blob_bytes(record["native_artifacts"]["result"])
    )
    executable = profile["version_argv"][0]
    commands = [
        [executable, "bqrs", "info", str(result), "--format=json"],
        [
            executable,
            "bqrs",
            "decode",
            "--format=json",
            "--entities=all",
            "--",
            str(result),
        ],
    ]
    capture = directory / label
    capture.mkdir()
    _deep_audit_io._codeql_steps_runner(
        [{"argv": argv, "accepted_exit_codes": [0]} for argv in commands],
        source,
        _deep_audit_io._codeql_replay_remaining(deadline),
        capture,
        expected_steps=2,
    )
    with _deep_audit_io.local_file(capture, "step-0/stdout.log").open("rb") as stream:
        sets = _deep_audit_io._codeql_result_sets(stream.read(65_537))
    if sets != record["result_sets"]:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_REPLAY", "independent result metadata differs"
        )
    with _deep_audit_io.local_file(capture, "step-1/stdout.log").open("rb") as stream:
        values = _deep_audit_io.strict_json(
            stream.read(_deep_audit_io.NATIVE_COVERAGE_LIMIT + 1)
        )
    return _deep_audit_io._codeql_replay_values(values, sets)


def _codeql_replay_values(values, sets):
    if set(values) != {item["name"] for item in sets}:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_REPLAY", "decoded result sets differ"
        )
    canonical = {}
    for item in sets:
        value = values[item["name"]]
        if set(value) != {"columns", "tuples"}:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_REPLAY", "unexpected decoded result fields"
            )
        columns, rows = value["columns"], value["tuples"]
        if not isinstance(columns, list) or len(columns) != item["columns"]:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_REPLAY", "decoded columns differ"
            )
        if not isinstance(rows, list) or len(rows) != item["rows"]:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_REPLAY", "decoded row count differs"
            )
        if any(not isinstance(row, list) or len(row) != len(columns) for row in rows):
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_REPLAY", "decoded tuple shape differs"
            )
        canonical[item["name"]] = {
            "columns": columns,
            "tuples": sorted(rows, key=_deep_audit_io.canonical_bytes),
        }
    return canonical


def _codeql_replay_sources(expected, actual, inventory, lane):
    for field in (  # noqa: F402 - preserve original audited function body
        "query_sha256",
        "package_sha256",
        "rows",
        "archived_sources",
    ):
        if expected[field] != actual[field]:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_REPLAY", "independent source measurement differs"
            )
    for measurement in (expected, actual):
        if (
            _deep_audit_io._codeql_source_accounting(measurement, inventory, lane)[
                "state"
            ]
            != "COMPLETE"
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_REPLAY", "source extraction is incomplete"
            )


def _codeql_challenges(profile, contract, source, lane, execution, started):
    obligations = [
        item
        for item in contract["obligations"]
        if item["engine"] == "codeql" and item["family"] == lane["family"]
    ]
    deadline = started + lane["timeout_seconds"]
    observations, gaps = [], []
    with _deep_audit_io.tempfile.TemporaryDirectory(
        prefix="factory-codeql-challenges-"
    ) as temporary:
        for index, obligation in enumerate(obligations):
            for challenge in obligation["challenges"]:
                _deep_audit_io._codeql_challenge_case(
                    profile,
                    contract,
                    source,
                    lane,
                    execution,
                    obligation,
                    challenge,
                    _deep_audit_io.Path(temporary)
                    / f"control-{index}-{challenge['kind']}",
                    deadline,
                    observations,
                    gaps,
                )
    return _deep_audit_io._challenge_bundle(observations, gaps), [
        item["id"] for item in obligations
    ]


def _codeql_challenge_case(
    profile,
    contract,
    source,
    lane,
    execution,
    obligation,
    challenge,
    case,
    deadline,
    observations,
    gaps,
):
    try:
        remaining = int(deadline - _deep_audit_io.time.monotonic())
        if remaining < 1:
            raise _deep_audit_io.RuntimeAuditError(
                "E_ADAPTER_TIMEOUT", "CodeQL challenge deadline exhausted"
            )
        observations.append(
            _deep_audit_io._run_codeql_challenge(
                profile,
                contract,
                source,
                lane,
                execution,
                obligation,
                challenge,
                case,
                remaining,
            )
        )
    except (
        OSError,
        _deep_audit_io.RuntimeAuditError,
        ValueError,
        TypeError,
        KeyError,
    ) as error:
        gaps.append(
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, _deep_audit_io._challenge_error_code(error)
            )
        )


def _codeql_challenge_inputs(
    profile, source, lane, execution, obligation, challenge, case
):
    if challenge.get("fixture_manifest") is None:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_CHALLENGE", "signed multi-file manifest required"
        )
    baseline = execution["codeql_query_inventory"]
    _deep_audit_io.verify_codeql_query_selection(baseline)
    if lane.get("rule_ids") != sorted(baseline["query_ids"]):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_CHALLENGE", "complete query ID lane required"
        )
    suite = _deep_audit_io.local_file(
        _deep_audit_io.Path(profile["commands"][1]["argv"][4]).parent,
        _deep_audit_io.Path(profile["commands"][1]["argv"][4]).name,
    )
    if (
        _deep_audit_io.sha256_bytes(_deep_audit_io._codeql_suite_bytes(suite))
        != baseline["suite_sha256"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_CHALLENGE", "baseline suite changed"
        )
    manifest = dict(sorted(challenge["fixture_manifest"].items()))
    _deep_audit_io._semgrep_fixture_binding(
        manifest, obligation, source, challenge["fixture_path"]
    )
    case.mkdir()
    root = case / "source"
    for path, seal in manifest.items():
        target = root.joinpath(*_deep_audit_io.relative_path(path).split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(
            _deep_audit_io.bound_bytes(source, {"path": path, "sha256": seal})
        )
    return suite, baseline, manifest, root


def _codeql_mutation_suite(case, suite, rule_id):
    _deep_audit_io.require_str(rule_id, "CodeQL target ID", maximum=256)
    root = _deep_audit_io.Path("/opt/codeql/codeql/qlpacks")
    relative = suite.relative_to(root).as_posix()
    _deep_audit_io.relative_path(relative)
    parts = relative.split("/")
    if len(parts) != 5 or parts[0] != "codeql" or parts[3] != "codeql-suites":
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_CHALLENGE", "pinned CodeQL suite location required"
        )
    raw = (
        f"- import: {parts[3]}/{parts[4]}\n  from: {parts[0]}/{parts[1]}\n  version: {parts[2]}\n- exclude:\n    id: {_deep_audit_io.json.dumps(rule_id)}\n"
    ).encode()
    path = case / "target-disabled.qls"
    path.write_bytes(raw)
    return path


def _codeql_challenge_selection(
    profile, root, case, suite, baseline, challenge, rule_id, deadline
):
    selected_suite = (
        _deep_audit_io._codeql_mutation_suite(case, suite, rule_id)
        if challenge["kind"] == "mutation"
        else suite
    )
    remaining = int(deadline - _deep_audit_io.time.monotonic())
    if remaining < 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "query selection deadline exhausted"
        )
    inventory = _deep_audit_io.resolve_codeql_query_inventory(
        profile["version_argv"][0], selected_suite, root, case, remaining
    )
    _deep_audit_io.verify_codeql_query_selection(
        inventory,
        baseline=baseline,
        disabled_rule_id=rule_id if challenge["kind"] == "mutation" else None,
    )
    return selected_suite, inventory


def _codeql_challenge_steps(profile, bindings, suite):
    commands = _deep_audit_io._native_argv(profile["commands"], bindings)
    if (
        len(commands) != 3
        or commands[0]["argv"][1:3] != ["database", "create"]
        or commands[1]["argv"][1:3] != ["database", "analyze"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_CHALLENGE", "pinned three-step CodeQL profile required"
        )
    commands[1]["argv"][4] = str(suite)
    return commands


def _codeql_steps_runner(commands, source, budget, scratch, *, expected_steps=3):
    from .runtime_audit_process import run_bounded_command
    from .runtime_audit_common import _validate_runner_facts

    started, invocations = _deep_audit_io.time.monotonic(), []
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    for index, command in enumerate(commands):
        remaining = int(budget - (_deep_audit_io.time.monotonic() - started))
        if remaining < 1:
            raise _deep_audit_io.RuntimeAuditError(
                "E_ADAPTER_TIMEOUT", "CodeQL steps exhausted deadline"
            )
        directory = scratch / f"step-{index}"
        directory.mkdir()
        out, err = directory / "stdout.log", directory / "stderr.log"
        facts = run_bounded_command(
            command["argv"],
            source,
            remaining,
            directory,
            stdout_path=out,
            stderr_path=err,
        )
        _validate_runner_facts(facts, remaining)
        if _deep_audit_io._adapter_command_failed(
            facts, command["accepted_exit_codes"], started + budget
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_CHALLENGE", "CodeQL native step failed or cleanup uncertain"
            )
        _deep_audit_io._codeql_step_streams(facts, out, err, streams)
        invocations.append(
            {
                "argv": command["argv"],
                "argv_sha256": _deep_audit_io.digest(command["argv"]),
                "execution": facts,
            }
        )
    return (
        _deep_audit_io._codeql_steps_facts(
            invocations, streams, started, budget, expected_steps
        ),
        invocations,
    )


def _codeql_step_streams(facts, out, err, streams):
    for role, path in (("stdout", out), ("stderr", err)):
        with _deep_audit_io.local_file(path.parent, path.name).open("rb") as stream:
            raw = stream.read(1_048_577)
        if (
            len(raw) > 1_048_576
            or _deep_audit_io.sha256_bytes(raw) != facts[role + "_sha256"]
            or len(raw) != facts[role + "_bytes"]
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_CHALLENGE", "native stream bytes differ"
            )
        streams[role].extend(raw)


def _run_codeql_challenge(
    profile, contract, source, lane, execution, obligation, challenge, case, timeout
):
    deadline = _deep_audit_io.time.monotonic() + timeout
    suite, baseline, manifest, root = _deep_audit_io._codeql_challenge_inputs(
        profile, source, lane, execution, obligation, challenge, case
    )
    rule_id = obligation["detector_rule_id"]
    selected, inventory = _deep_audit_io._codeql_challenge_selection(
        profile, root, case, suite, baseline, challenge, rule_id, deadline
    )
    return _deep_audit_io._execute_codeql_challenge(
        profile,
        contract,
        lane,
        execution,
        obligation,
        challenge,
        case,
        root,
        manifest,
        suite,
        selected,
        baseline,
        inventory,
        deadline,
    )


def _execute_codeql_challenge(
    profile,
    contract,
    lane,
    execution,
    obligation,
    challenge,
    case,
    root,
    manifest,
    suite,
    selected,
    baseline,
    inventory,
    deadline,
):
    scratch = case / "run"
    report, ledger, artifact = (
        scratch / "report.sarif",
        scratch / "unused-ledger.json",
        scratch / "query-inventory.json",
    )
    bindings = _deep_audit_io._native_challenge_bindings(
        root, scratch, report, ledger, selected, _deep_audit_io.digest(manifest)
    )
    commands = _deep_audit_io._codeql_challenge_steps(profile, bindings, selected)
    configs = {
        _deep_audit_io._codeql_suite_bytes(suite): baseline,
        _deep_audit_io._codeql_suite_bytes(selected): inventory,
    }

    def runner(argv, cwd, budget, run_scratch):
        if argv != commands[0]["argv"]:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_CHALLENGE", "create argv differs from profile"
            )
        facts, invocations = _deep_audit_io._codeql_steps_runner(
            commands, cwd, budget, run_scratch
        )
        inventory["native_invocations"] = invocations
        artifact.write_bytes(_deep_audit_io.canonical_bytes(inventory))
        return facts

    def parser(raw):
        return _deep_audit_io._codeql_challenge_report(raw, profile, root, manifest)

    def rule_ids(raw):
        return sorted(configs[raw]["query_ids"])

    def mutation_valid(original, effective, rule_id):
        _deep_audit_io.verify_codeql_query_selection(
            configs[effective], baseline=configs[original], disabled_rule_id=rule_id
        )
        return True

    remaining = int(deadline - _deep_audit_io.time.monotonic())
    if remaining < 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "native challenge deadline exhausted"
        )
    observation = _deep_audit_io._native_challenge_executor()(
        challenge,
        obligation_id=obligation["id"],
        engine="codeql",
        detector_rule_id=obligation["detector_rule_id"],
        detector_enabled=challenge["kind"] != "mutation",
        profile_argv=profile["commands"][0]["argv"],
        bindings=bindings,
        source_root=root,
        baseline_config_path=suite,
        effective_config_path=selected,
        report_path=report,
        ledger_path=ledger,
        scratch=scratch,
        scratch_parent=case,
        timeout_seconds=remaining,
        expected_ruleset_sha256=baseline["suite_sha256"],
        execution_bindings={
            "candidate_sha256": contract["inventory"]["candidate_sha256"],
            "challenge_source_sha256": _deep_audit_io.digest(manifest),
            "profile_sha256": _deep_audit_io.digest(profile),
            "image_sha256": _deep_audit_io.sha256_bytes(lane["image"].encode()),
            "tool_version": profile["tool_version"],
            "version_probe_sha256": _deep_audit_io.digest(execution["version_probe"]),
            "version_probe_facts": execution["version_probe"],
        },
        runner=runner,
        report_parser=parser,
        config_rule_ids=rule_ids,
        verify_mutation=mutation_valid,
        native_artifact_roles=lane["native_artifact_roles"],
        native_artifacts={"sarif_report": report, "query_inventory": artifact},
        rule_ids=lane["rule_ids"],
        mutation_ruleset_sha256=lane["mutation_config_sha256"],
    )
    observation["codeql_query_inventory"] = inventory
    return observation


def _codeql_challenge_report(raw, profile, root, manifest):
    report = _deep_audit_io._semgrep_challenge_report(raw, profile, root, manifest)
    report.get("properties", {}).pop("factory_native_raw_sha256", None)
    for run in report["runs"]:
        for invocation in run.get("invocations", []):
            notifications = invocation.get("toolExecutionNotifications", [])
            invocation["toolExecutionNotifications"] = sorted(
                [
                    item
                    for item in notifications
                    if not _deep_audit_io._codeql_telemetry_notification(item)
                ],
                key=_deep_audit_io.canonical_bytes,
            )
    return report


def _codeql_telemetry_notification(item):
    return item.get("level") == "none" and item.get("descriptor", {}).get("id") in {
        "cli/file-coverage-baseline",
        "cli/platform",
        "cli/build-mode",
    }


def _trivy_challenges(profile, contract, source, lane, execution, started):
    from .runtime_audit_process import run_bounded_command

    obligations = _deep_audit_io._trivy_obligations(contract, lane)
    observations, gaps = [], []
    if not lane.get("native_policy"):
        gaps = [
            _deep_audit_io._challenge_gap_record(item, control, "E_TRIVY_POLICY")
            for item in obligations
            for control in item["challenges"]
        ]
        return _deep_audit_io._challenge_bundle(observations, gaps), [
            item["id"] for item in obligations
        ]
    if len(obligations) > 64:
        gaps = [
            _deep_audit_io._challenge_gap_record(
                item, control, "E_TRIVY_CHALLENGE_BUDGET"
            )
            for item in obligations
            for control in item["challenges"]
        ]
        return _deep_audit_io._challenge_bundle(observations, gaps), [
            item["id"] for item in obligations
        ]
    config = _deep_audit_io.Path("/opt/factory/rules/trivy.yaml").read_bytes()
    baseline_path = _deep_audit_io.Path("/opt/factory/rules/empty-trivyignore")
    baseline = baseline_path.read_bytes()
    _deep_audit_io._trivy_policy_inputs(config, baseline, lane)
    command = _deep_audit_io._trivy_challenge_command(profile)
    source_bindings = {
        item["path"]: item["sha256"] for item in contract["inventory"]["files"]
    }
    deadline = started + lane["timeout_seconds"]
    with _deep_audit_io.tempfile.TemporaryDirectory(
        prefix="factory-trivy-challenges-"
    ) as root:
        for index, obligation in enumerate(obligations):
            for challenge in obligation["challenges"]:
                _deep_audit_io._trivy_challenge_control(
                    run_bounded_command,
                    profile,
                    contract,
                    source,
                    lane,
                    execution,
                    command,
                    config,
                    baseline_path,
                    baseline,
                    source_bindings,
                    obligation,
                    challenge,
                    _deep_audit_io.Path(root) / f"control-{index}-{challenge['kind']}",
                    deadline,
                    observations,
                    gaps,
                )
    return _deep_audit_io._challenge_bundle(observations, gaps), [
        item["id"] for item in obligations
    ]


def _challenge_bundle(observations, gaps):
    return {
        "schema": "factory.deep-challenges.v1",
        "observations": observations,
        "gaps": gaps,
    }


def _trivy_obligations(contract, lane):
    return [
        item
        for item in contract["obligations"]
        if item["engine"] == "trivy" and item["family"] == lane["family"]
    ]


def _trivy_challenge_command(profile):
    if profile.get("engine") != "trivy" or len(profile.get("commands", [])) != 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_PROFILE", "one pinned Trivy command required"
        )
    argv = list(profile["commands"][0].get("argv", []))
    try:
        if argv[argv.index("--format") + 1] != "sarif":
            raise ValueError
        argv[argv.index("--output") + 1] = "{report}"
        argv[argv.index("--ignorefile") + 1] = "{config}"
        if argv[-1] != "{source}":
            raise ValueError
    except (ValueError, IndexError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_PROFILE", "pinned command template differs"
        ) from exc
    return {
        "argv": argv,
        "accepted_exit_codes": profile["commands"][0]["accepted_exit_codes"],
    }


def _trivy_challenge_control(
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    config,
    baseline_path,
    baseline,
    source_bindings,
    obligation,
    challenge,
    case,
    deadline,
    observations,
    gaps,
):
    remaining = int(deadline - _deep_audit_io.time.monotonic())
    fixture_path = challenge.get("fixture_path")
    fixture_map = challenge.get(
        "fixture_manifest", {fixture_path: challenge.get("fixture_sha256")}
    )
    if remaining < 1:
        gaps.append(
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, "E_ADAPTER_TIMEOUT"
            )
        )
        return
    if not _deep_audit_io._gitleaks_challenge_allowed(
        challenge, obligation, source_bindings, command, lane
    ):
        gaps.append(
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, "E_CHALLENGE_BINDING"
            )
        )
        return
    if (
        not isinstance(fixture_map, dict)
        or not set(obligation.get("paths", [])) <= set(source_bindings)
        or not set(fixture_map) <= set(obligation["paths"])
    ):
        gaps.append(
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, "E_CHALLENGE_BINDING"
            )
        )
        return
    try:
        observations.append(
            _deep_audit_io._run_trivy_challenge(
                _deep_audit_io._native_challenge_executor(),
                runner,
                profile,
                contract,
                source,
                lane,
                execution,
                command,
                config,
                baseline_path,
                baseline,
                obligation,
                challenge,
                fixture_map,
                case,
                remaining,
            )
        )
    except (
        OSError,
        _deep_audit_io.RuntimeAuditError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        gaps.append(
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, _deep_audit_io._challenge_error_code(exc)
            )
        )


def _run_trivy_challenge(
    execute,
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    config,
    baseline_path,
    baseline,
    obligation,
    challenge,
    fixture_map,
    case,
    timeout,
):
    from .runtime_audit_common import sha256_bytes as common_sha256

    case.mkdir()
    challenge_root = case / "source"
    fixture_map = dict(sorted(fixture_map.items()))
    for path, source_sha in fixture_map.items():
        target = challenge_root.joinpath(*_deep_audit_io.relative_path(path).split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(
            _deep_audit_io.bound_bytes(source, {"path": path, "sha256": source_sha})
        )
    challenge_sha = _deep_audit_io.digest(fixture_map)
    effective = baseline_path
    if challenge["kind"] == "mutation":
        effective = _deep_audit_io._trivy_mutation_path(
            case, baseline, lane, obligation
        )
    scratch = case / "run"
    report_path, policy_path = scratch / "report.sarif", scratch / "policy.json"
    argv = dict(
        source=str(challenge_root),
        output=str(scratch),
        report=str(report_path),
        scratch=str(scratch),
        candidate_sha256=challenge_sha,
        factory_ledger=str(scratch / "unused-ledger.json"),
        config=str(effective),
    )
    paired = {}

    def challenge_runner(rendered, cwd, budget, run_scratch):
        return _deep_audit_io._trivy_paired_runner(
            runner, rendered, cwd, budget, run_scratch, policy_path, paired
        )

    def report_parser(raw):
        paired["sarif_raw"] = raw
        source_bytes = _deep_audit_io._trivy_source_bytes(challenge_root, fixture_map)
        matrix = _deep_audit_io._trivy_native_checks(
            _deep_audit_io.strict_json(paired["json_raw"]),
            fixture_map,
            _deep_audit_io._trivy_target_bindings(
                _deep_audit_io.strict_json(paired["json_raw"]),
                fixture_map,
                source_bytes,
            ),
        )
        return _deep_audit_io._trivy_challenge_report(
            raw, profile, challenge_root, fixture_map, matrix
        )

    image = lane["image"]
    bindings = {
        "candidate_sha256": contract["inventory"]["candidate_sha256"],
        "challenge_source_sha256": challenge_sha,
        "profile_sha256": _deep_audit_io.digest(profile),
        "image_sha256": common_sha256(image.encode("utf-8")),
        "tool_version": profile["tool_version"],
        "version_probe_sha256": _deep_audit_io.digest(execution["version_probe"]),
        "version_probe_facts": execution["version_probe"],
    }
    observation = execute(
        challenge,
        obligation_id=obligation["id"],
        engine="trivy",
        detector_rule_id=obligation["detector_rule_id"],
        detector_enabled=challenge["kind"] != "mutation",
        profile_argv=command["argv"],
        bindings=argv,
        source_root=challenge_root,
        baseline_config_path=baseline_path,
        effective_config_path=effective,
        report_path=report_path,
        ledger_path=scratch / "unused-ledger.json",
        scratch=scratch,
        scratch_parent=case,
        timeout_seconds=timeout,
        expected_ruleset_sha256=lane["native_policy"]["baseline_ignore_sha256"],
        execution_bindings=bindings,
        runner=challenge_runner,
        report_parser=report_parser,
        config_rule_ids=lambda raw: _deep_audit_io._trivy_effective_ids(raw, lane),
        verify_mutation=_deep_audit_io._trivy_mutation_valid,
        native_artifact_roles=lane["native_artifact_roles"],
        native_artifacts={"sarif_report": report_path, "policy_inventory": policy_path},
        rule_ids=lane["rule_ids"],
        mutation_ruleset_sha256=lane["mutation_config_sha256"],
    )
    observation["trivy_rule_execution"] = _deep_audit_io._trivy_challenge_evidence(
        config, effective.read_bytes(), fixture_map, paired, observation, challenge_root
    )
    checked = _deep_audit_io.verify_trivy_rule_execution(
        observation["trivy_rule_execution"],
        lane,
        fixture_map,
        observation["report"]["native_report"],
        disabled_rule_id=obligation["detector_rule_id"]
        if challenge["kind"] == "mutation"
        else None,
    )
    if checked["state"] != "VERIFIED":
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "paired native evidence did not verify"
        )
    return observation


def _trivy_mutation_path(case, baseline, lane, obligation):
    rule_id = obligation["detector_rule_id"]
    effective = _deep_audit_io._trivy_mutation(baseline, rule_id)
    expected = lane.get("mutation_config_sha256", {}).get(rule_id)
    if _deep_audit_io.sha256_bytes(effective) != expected:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_MUTATION_BINDING", "signed ignorefile digest differs"
        )
    path = case / "mutation-trivyignore"
    path.write_bytes(effective)
    return path


def _trivy_effective_ids(ignore, lane):
    excluded = set(_deep_audit_io._trivy_ignore_ids(ignore))
    ids = lane.get("rule_ids")
    if not isinstance(ids, list) or not excluded <= set(ids):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_POLICY", "ignore IDs exceed signed checks"
        )
    return [rule for rule in ids if rule not in excluded]


def _trivy_challenge_report(raw, profile, source_root, sources, matrix):
    report = _deep_audit_io.strict_json(raw)
    if not isinstance(report, dict):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CHALLENGE_REPORT", "native SARIF object required"
        )
    report = _deep_audit_io._native_sarif_metadata(report, profile, [])
    _deep_audit_io._normalize_challenge_sarif_paths(report, source_root)
    report = _deep_audit_io._native_sarif_paths(report, sources)
    status_rows = [
        {
            "source": path,
            "checks": [
                {"id": rule, "status": status} for rule, status in sorted(rows.items())
            ],
        }
        for path, rows in sorted(matrix.items())
    ]
    for run in report["runs"]:
        properties = run.setdefault("properties", {})
        if not isinstance(properties, dict):
            raise _deep_audit_io.RuntimeAuditError(
                "E_CHALLENGE_REPORT", "SARIF properties malformed"
            )
        properties["factory_trivy_checks"] = status_rows
    return report


def _gitleaks_challenges_complete(challenges, obligations):
    if challenges.get("gaps"):
        return False
    expected = {
        (identity, kind)
        for identity in obligations
        for kind in ("positive", "negative", "mutation")
    }
    observed = set()
    all_verified = True
    for item in challenges.get("observations", []):
        identity = (item.get("obligation_id"), item.get("kind"))
        if identity in observed:
            all_verified = False
        observed.add(identity)
        all_verified = (
            all_verified
            and isinstance(item.get("execution"), dict)
            and item["execution"].get("status") == "VERIFIED"
            and isinstance(item.get("report"), dict)
            and item.get("observation_sha256") == _deep_audit_io.digest(item["report"])
        )
    return bool(expected) and observed == expected and all_verified


def _gitleaks_challenges(profile, contract, source, lane, execution, started):
    from .runtime_audit_common import execute_native_challenge
    from .runtime_audit_process import run_bounded_command

    commands = profile["commands"]
    if len(commands) != 1:
        return {"schema": "factory.deep-challenges.v1", "observations": []}, []
    command = commands[0]
    source_bindings = {
        item["path"]: item["sha256"] for item in contract["inventory"]["files"]
    }
    obligations = _deep_audit_io._gitleaks_obligations(contract, lane)
    ids = sorted(item["id"] for item in obligations)
    baseline_path = _deep_audit_io.Path("/opt/factory/rules/gitleaks.toml")
    baseline = baseline_path.read_bytes()
    observations = []
    gaps = []
    deadline = started + lane["timeout_seconds"]
    with _deep_audit_io.tempfile.TemporaryDirectory(
        prefix="factory-gitleaks-challenges-"
    ) as temporary:
        root = _deep_audit_io.Path(temporary)
        for index, obligation in enumerate(obligations):
            for challenge in obligation["challenges"]:
                remaining = int(deadline - _deep_audit_io.time.monotonic())
                if remaining < 1:
                    gaps.append(
                        _deep_audit_io._challenge_gap_record(
                            obligation, challenge, "E_ADAPTER_TIMEOUT"
                        )
                    )
                    continue
                if not _deep_audit_io._gitleaks_challenge_allowed(
                    challenge, obligation, source_bindings, command, lane
                ):
                    gaps.append(
                        _deep_audit_io._challenge_gap_record(
                            obligation, challenge, "E_CHALLENGE_BINDING"
                        )
                    )
                    continue
                try:
                    observation = _deep_audit_io._run_gitleaks_challenge(
                        execute_native_challenge,
                        run_bounded_command,
                        profile,
                        contract,
                        source,
                        lane,
                        execution,
                        command,
                        challenge,
                        obligation,
                        source_bindings,
                        baseline_path,
                        baseline,
                        root / f"control-{index}-{challenge['kind']}",
                        remaining,
                    )
                except (
                    OSError,
                    _deep_audit_io.RuntimeAuditError,
                    ValueError,
                    TypeError,
                    KeyError,
                ) as exc:
                    gaps.append(
                        _deep_audit_io._challenge_gap_record(
                            obligation,
                            challenge,
                            _deep_audit_io._challenge_error_code(exc),
                        )
                    )
                    continue
                observations.append(observation)
    return {
        "schema": "factory.deep-challenges.v1",
        "observations": observations,
        "gaps": gaps,
    }, ids


def _runtime_challenges(profile, contract, source, lane, execution, started):
    from .runtime_audit_common import execute_native_challenge
    from .runtime_audit_process import run_bounded_command

    obligations = _deep_audit_io._runtime_obligations(contract, lane)
    observations, gaps = [], []
    source_bindings = {
        item["path"]: item["sha256"] for item in contract["inventory"]["files"]
    }
    command = profile["commands"][0]
    baseline_path = _deep_audit_io.Path("/opt/factory/rules/runtime-control.toml")
    baseline = baseline_path.read_bytes()
    deadline = started + lane["timeout_seconds"]
    with _deep_audit_io.tempfile.TemporaryDirectory(
        prefix="factory-runtime-challenges-"
    ) as root:
        for index, obligation in enumerate(obligations):
            for challenge in obligation["challenges"]:
                try:
                    observation = _deep_audit_io._runtime_challenge(
                        execute_native_challenge,
                        run_bounded_command,
                        profile,
                        contract,
                        source,
                        lane,
                        execution,
                        command,
                        challenge,
                        obligation,
                        source_bindings,
                        baseline_path,
                        baseline,
                        _deep_audit_io.Path(root)
                        / f"control-{index}-{challenge['kind']}",
                        deadline,
                    )
                    observations.append(observation)
                except (
                    OSError,
                    _deep_audit_io.RuntimeAuditError,
                    ValueError,
                    TypeError,
                    KeyError,
                ) as exc:
                    gaps.append(
                        _deep_audit_io._challenge_gap_record(
                            obligation,
                            challenge,
                            _deep_audit_io._challenge_error_code(exc),
                        )
                    )
    return {
        "schema": "factory.deep-challenges.v1",
        "observations": observations,
        "gaps": gaps,
    }, [item["id"] for item in obligations]


def _semgrep_challenges(profile, contract, source, lane, execution, started):
    from .runtime_audit_process import run_bounded_command

    command = _deep_audit_io._semgrep_challenge_command(profile)
    baseline_path = _deep_audit_io.Path(
        "/opt/factory/rules/semgrep-pattern-limited.yml"
    )
    baseline = baseline_path.read_bytes()
    _deep_audit_io._semgrep_rule_inventory(baseline, lane)
    source_bindings = {
        item["path"]: item["sha256"] for item in contract["inventory"]["files"]
    }
    obligations = _deep_audit_io._semgrep_obligations(contract, lane)
    observations, gaps = [], []
    if len(obligations) > 64:
        gaps = [
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, "E_SEMGREP_CHALLENGE_BUDGET"
            )
            for obligation in obligations
            for challenge in obligation["challenges"]
        ]
        return {
            "schema": "factory.deep-challenges.v1",
            "observations": observations,
            "gaps": gaps,
        }, [item["id"] for item in obligations]
    deadline = started + lane["timeout_seconds"]
    with _deep_audit_io.tempfile.TemporaryDirectory(
        prefix="factory-semgrep-challenges-"
    ) as root:
        for index, obligation in enumerate(obligations):
            for challenge in obligation["challenges"]:
                _deep_audit_io._semgrep_challenge_result(
                    execute_native_challenge=_deep_audit_io._native_challenge_executor(),
                    runner=run_bounded_command,
                    profile=profile,
                    contract=contract,
                    source=source,
                    lane=lane,
                    execution=execution,
                    command=command,
                    baseline_path=baseline_path,
                    baseline=baseline,
                    source_bindings=source_bindings,
                    obligation=obligation,
                    challenge=challenge,
                    case=_deep_audit_io.Path(root)
                    / f"control-{index}-{challenge['kind']}",
                    deadline=deadline,
                    observations=observations,
                    gaps=gaps,
                )
    return {
        "schema": "factory.deep-challenges.v1",
        "observations": observations,
        "gaps": gaps,
    }, [item["id"] for item in obligations]


def _semgrep_obligations(contract, lane):
    return [
        item
        for item in contract["obligations"]
        if item["engine"] == "semgrep" and item["family"] == lane["family"]
    ]


def _semgrep_challenge_result(
    *,
    execute_native_challenge,
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    baseline_path,
    baseline,
    source_bindings,
    obligation,
    challenge,
    case,
    deadline,
    observations,
    gaps,
):
    remaining = int(deadline - _deep_audit_io.time.monotonic())
    if remaining < 1:
        gaps.append(
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, "E_ADAPTER_TIMEOUT"
            )
        )
        return
    if not _deep_audit_io._gitleaks_challenge_allowed(
        challenge, obligation, source_bindings, command, lane
    ):
        gaps.append(
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, "E_CHALLENGE_BINDING"
            )
        )
        return
    try:
        observations.append(
            _deep_audit_io._run_semgrep_challenge(
                execute_native_challenge,
                runner,
                profile,
                contract,
                source,
                lane,
                execution,
                command,
                baseline_path,
                baseline,
                obligation,
                challenge,
                case,
                remaining,
            )
        )
    except (
        OSError,
        _deep_audit_io.RuntimeAuditError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        gaps.append(
            _deep_audit_io._challenge_gap_record(
                obligation, challenge, _deep_audit_io._challenge_error_code(exc)
            )
        )


def _semgrep_challenge_command(profile):
    if profile.get("engine") != "semgrep" or len(profile.get("commands", [])) != 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_PROFILE", "one pinned Semgrep command required"
        )
    argv = profile["commands"][0].get("argv")
    expected = [
        "/usr/bin/semgrep",
        "scan",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--disable-nosem",
        "--dataflow-traces",
        "--config",
        "/opt/factory/rules/semgrep-pattern-limited.yml",
        "--sarif-output",
        "{report}",
        "{source}",
    ]
    if argv != expected:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_PROFILE", "pinned command differs"
        )
    result = list(argv)
    result[8] = "{config}"
    result.insert(7, "--no-rewrite-rule-ids")
    return {
        "argv": result,
        "accepted_exit_codes": profile["commands"][0]["accepted_exit_codes"],
    }


def _run_semgrep_challenge(
    execute,
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    baseline_path,
    baseline,
    obligation,
    challenge,
    case,
    timeout,
):
    from .runtime_audit_common import sha256_bytes as common_sha256

    fixture_path = _deep_audit_io.relative_path(challenge["fixture_path"])
    fixture_manifest = dict(
        sorted(
            challenge.get(
                "fixture_manifest", {fixture_path: challenge["fixture_sha256"]}
            ).items()
        )
    )
    _deep_audit_io._semgrep_fixture_binding(
        fixture_manifest, obligation, source, fixture_path
    )
    case.mkdir()
    challenge_root = case / "source"
    for path, source_sha in fixture_manifest.items():
        target = challenge_root.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(
            _deep_audit_io.bound_bytes(source, {"path": path, "sha256": source_sha})
        )
    challenge_sha = _deep_audit_io.digest(fixture_manifest)
    config_path = baseline_path
    if challenge["kind"] == "mutation":
        config_path = _deep_audit_io._semgrep_mutation_file(
            case, baseline, lane, obligation
        )
    scratch = case / "run"
    report_path = scratch / "report.sarif"
    inventory_path = scratch / "rule-inventory.json"
    ledger_path = scratch / "unused-ledger.json"
    bindings = _deep_audit_io._native_challenge_bindings(
        challenge_root, scratch, report_path, ledger_path, config_path, challenge_sha
    )
    effective = config_path.read_bytes()
    effective_ids = _deep_audit_io._semgrep_rule_ids(effective)
    inventory_bytes = _deep_audit_io.canonical_bytes(
        {
            "ruleset_sha256": _deep_audit_io.sha256_bytes(effective),
            "rule_ids": effective_ids,
        }
    )

    def challenge_runner(argv, cwd, budget, run_scratch):
        inventory_path.write_bytes(inventory_bytes)
        return runner(argv, cwd, budget, run_scratch)

    def report_parser(raw):
        return _deep_audit_io._semgrep_challenge_report(
            raw, profile, challenge_root, fixture_manifest
        )

    image = lane["image"]
    execution_bindings = {
        "candidate_sha256": contract["inventory"]["candidate_sha256"],
        "challenge_source_sha256": challenge_sha,
        "profile_sha256": _deep_audit_io.digest(profile),
        "image_sha256": common_sha256(image.encode("utf-8")),
        "tool_version": profile["tool_version"],
        "version_probe_sha256": _deep_audit_io.digest(execution["version_probe"]),
        "version_probe_facts": execution["version_probe"],
    }
    return execute(
        challenge,
        obligation_id=obligation["id"],
        engine="semgrep",
        detector_rule_id=obligation["detector_rule_id"],
        detector_enabled=challenge["kind"] != "mutation",
        profile_argv=command["argv"],
        bindings=bindings,
        source_root=challenge_root,
        baseline_config_path=baseline_path,
        effective_config_path=config_path,
        report_path=report_path,
        ledger_path=ledger_path,
        scratch=scratch,
        scratch_parent=case,
        timeout_seconds=timeout,
        expected_ruleset_sha256=lane["ruleset_sha256"],
        execution_bindings=execution_bindings,
        runner=challenge_runner,
        report_parser=report_parser,
        config_rule_ids=_deep_audit_io._semgrep_rule_ids,
        verify_mutation=_deep_audit_io._semgrep_mutation_valid,
        native_artifact_roles=lane["native_artifact_roles"],
        native_artifacts={
            "sarif_report": report_path,
            "rule_inventory": inventory_path,
        },
        rule_ids=lane["rule_ids"],
        mutation_ruleset_sha256=lane["mutation_config_sha256"],
    )


def _semgrep_challenge_report(raw, profile, source_root, sources):
    report = _deep_audit_io.strict_json(raw)
    if not isinstance(report, dict):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CHALLENGE_REPORT", "native SARIF object required"
        )
    report = _deep_audit_io._native_sarif_metadata(report, profile, [])
    _deep_audit_io._normalize_challenge_sarif_paths(report, source_root)
    return _deep_audit_io._native_sarif_paths(report, sources)


def _runtime_obligations(contract, lane):
    required = {
        item["path"]
        for item in contract["inventory"]["files"]
        if item["language"] in lane["languages"]
    }
    candidates = [
        item
        for item in contract["obligations"]
        if item["engine"] == "runtime" and item["family"] == lane["family"]
    ]
    items = [item for item in candidates if set(item["paths"]) <= required]
    if len(items) > 64:
        _deep_audit_io._native_budget_error(
            "E_RUNTIME_CHALLENGE_BUDGET", len(items), 3, len(items) * 3, 192
        )
    return items


def _runtime_challenge(
    execute,
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    challenge,
    obligation,
    source_bindings,
    baseline_path,
    baseline,
    case,
    deadline,
):
    from .runtime_audit_common import sha256_bytes as common_sha256

    if not _deep_audit_io._gitleaks_challenge_allowed(
        challenge, obligation, source_bindings, command, lane
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CHALLENGE_BINDING", "runtime challenge is not bound"
        )
    remaining = int(deadline - _deep_audit_io.time.monotonic())
    if remaining < 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "runtime challenge budget exhausted"
        )
    fixture_path = _deep_audit_io.relative_path(challenge["fixture_path"])
    fixture_sha = challenge["fixture_sha256"]
    manifest = dict(
        sorted(challenge.get("fixture_manifest", {fixture_path: fixture_sha}).items())
    )
    case.mkdir()
    challenge_root = case / "source"
    for path, source_sha in manifest.items():
        target = challenge_root.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(
            _deep_audit_io.bound_bytes(source, {"path": path, "sha256": source_sha})
        )
    source_sha = _deep_audit_io.digest(manifest)
    config_path = baseline_path
    if challenge["kind"] == "mutation":
        config_path = _deep_audit_io._runtime_mutation_config(
            case, baseline, lane, obligation
        )
    scratch = case / "run"
    report_path, coverage_path = scratch / "runtime.xml", scratch / "coverage.json"
    bindings = {
        "source": str(challenge_root),
        "output": str(scratch),
        "report": str(report_path),
        "scratch": str(scratch),
        "candidate_sha256": source_sha,
        "factory_ledger": str(coverage_path),
        "config": str(config_path),
    }

    def parse_report(raw):
        return _deep_audit_io._runtime_challenge_report(
            raw, coverage_path, manifest, lane, challenge
        )

    image = lane["image"]
    bound = {
        "candidate_sha256": contract["inventory"]["candidate_sha256"],
        "challenge_source_sha256": source_sha,
        "profile_sha256": _deep_audit_io.digest(profile),
        "image_sha256": common_sha256(image.encode()),
        "tool_version": profile["tool_version"],
        "version_probe_sha256": _deep_audit_io.digest(execution["version_probe"]),
        "version_probe_facts": execution["version_probe"],
    }
    return execute(
        challenge,
        obligation_id=obligation["id"],
        engine="runtime",
        detector_rule_id=obligation["detector_rule_id"],
        detector_enabled=challenge["kind"] != "mutation",
        profile_argv=_deep_audit_io._runtime_encoded_argv(command["argv"]),
        bindings=bindings,
        source_root=challenge_root,
        baseline_config_path=baseline_path,
        effective_config_path=config_path,
        report_path=report_path,
        ledger_path=coverage_path,
        scratch=scratch,
        scratch_parent=case,
        timeout_seconds=remaining,
        expected_ruleset_sha256=lane["ruleset_sha256"],
        execution_bindings=bound,
        runner=runner,
        report_parser=parse_report,
        config_rule_ids=_deep_audit_io._runtime_rule_ids,
        verify_mutation=_deep_audit_io._runtime_mutation_valid,
        native_artifact_roles=lane["native_artifact_roles"],
        native_artifacts={"junit_xml": report_path, "coverage_json": coverage_path},
        rule_ids=lane["rule_ids"],
        mutation_ruleset_sha256=lane["mutation_config_sha256"],
    )


def _runtime_encoded_argv(argv):
    import base64

    result = list(argv)
    try:
        code_index = result.index("-c") + 1
        code = result[code_index].encode("utf-8")
    except (ValueError, IndexError, AttributeError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_PROFILE", "runtime profile command malformed"
        ) from exc
    encoded = base64.b64encode(code).decode("ascii")
    result[code_index] = f"exec(__import__('base64').b64decode('{encoded}'))"
    return result


def _runtime_mutation_config(case, baseline, lane, obligation):
    rule_id = obligation["detector_rule_id"]
    changed = _deep_audit_io._runtime_disable_rule(baseline, rule_id)
    expected = lane.get("mutation_config_sha256", {}).get(rule_id)
    if (
        _deep_audit_io.sha256_bytes(changed) != expected
        or _deep_audit_io._runtime_rule_ids(changed) != []
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_MUTATION_BINDING", "signed mutation config differs"
        )
    path = case / "mutation.toml"
    path.write_bytes(changed)
    return path


def _runtime_challenge_report(junit, coverage_path, manifest, lane, challenge):
    if (
        len(junit) > _deep_audit_io.LIMIT
        or b"<!DOCTYPE" in junit.upper()
        or b"<!ENTITY" in junit.upper()
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_REPORT", "unsafe or oversized JUnit"
        )
    tests, findings, harness, _junit_hash = _deep_audit_io._parse_runtime_junit(
        junit, manifest
    )
    if challenge["kind"] == "positive" and not any(
        finding["path"] == challenge["fixture_path"] for finding in findings
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CHALLENGE_SEMANTICS", "positive runtime control did not fail"
        )
    if challenge["kind"] in {"negative", "mutation"} and findings:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CHALLENGE_SEMANTICS", "clean runtime control failed"
        )
    if challenge["kind"] == "mutation" and not _deep_audit_io._runtime_has_sentinel(
        junit, challenge["fixture_path"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_SENTINEL", "mutation control lacks a passing sentinel"
        )
    artifact = _deep_audit_io.local_file(coverage_path.parent, "coverage.json")
    with artifact.open("rb") as stream:
        coverage = _deep_audit_io.strict_json(stream.read(_deep_audit_io.LIMIT + 1))
    if coverage.get("meta", {}).get("branch_coverage") is not True:
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "native branch coverage missing"
        )
    native = {
        "schema": "factory.deep-runtime-observations.v1",
        "engine": "runtime",
        "tool_version": lane["tool_version"],
        "completed": True,
        "errors": [],
        "harness": harness,
        "metrics": {"tests": tests},
        "findings": findings,
        "source_coverage": _deep_audit_io._native_source_counts(coverage, manifest),
    }
    return native


def _runtime_has_sentinel(junit, target_path):
    import xml.etree.ElementTree as ET

    root = ET.fromstring(junit)
    target = _deep_audit_io.relative_path(target_path)
    return any(
        _deep_audit_io.relative_path(item.get("file", "").removeprefix("/src/"))
        != target
        and item.find("failure") is None
        and item.find("error") is None
        and item.find("skipped") is None
        for item in root.iter("testcase")
    )


def _gitleaks_obligations(contract, lane):
    required = {
        item["path"]
        for item in contract["inventory"]["files"]
        if item["language"] in lane["languages"]
    }
    obligations = [
        item
        for item in contract["obligations"]
        if item["engine"] == "gitleaks"
        and item["family"] == lane["family"]
        and set(item["paths"]) <= required
    ]
    if len(obligations) > 64:
        _deep_audit_io._native_budget_error(
            "E_GITLEAKS_CHALLENGE_BUDGET",
            len(obligations),
            3,
            len(obligations) * 3,
            64 * 3,
        )
    return obligations


def _challenge_gap_record(obligation, challenge, reason):
    return {
        "obligation_id": obligation["id"],
        "kind": challenge.get("kind") if isinstance(challenge, dict) else None,
        "reason": reason,
    }


def _challenge_error_code(error):
    code = getattr(error, "code", None)
    if (
        isinstance(code, str)
        and code.startswith("E_")
        and code.replace("_", "").isalnum()
        and code == code.upper()
        and len(code) <= 58
    ):
        return code
    return "E_CHALLENGE_EXECUTION"


def _gitleaks_challenge_allowed(challenge, obligation, source_bindings, command, lane):
    accepted = command["accepted_exit_codes"]
    manifest = challenge.get("fixture_manifest")
    if manifest is not None and (
        not isinstance(manifest, dict)
        or not 1 <= len(manifest) <= 64
        or any(source_bindings.get(path) != sha for path, sha in manifest.items())
    ):
        return False
    return (
        challenge.get("fixture_path") in source_bindings
        and challenge.get("fixture_sha256")
        == source_bindings.get(challenge.get("fixture_path"))
        and obligation["detector_rule_id"] in lane["rule_ids"]
        and challenge.get("expected_exit_code") in accepted
    )


def _run_gitleaks_challenge(
    execute,
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    challenge,
    obligation,
    source_bindings,
    baseline_path,
    baseline,
    case,
    timeout,
):
    from .runtime_audit_common import sha256_bytes as common_sha256

    fixture_path = _deep_audit_io.relative_path(challenge["fixture_path"])
    fixture_sha = challenge["fixture_sha256"]
    fixture_manifest = challenge.get("fixture_manifest", {fixture_path: fixture_sha})
    case.mkdir()
    challenge_root = case / "source"
    challenge_inventory = dict(sorted(fixture_manifest.items()))
    for path, source_sha in challenge_inventory.items():
        fixture = _deep_audit_io.bound_bytes(
            source, {"path": path, "sha256": source_sha}
        )
        target = challenge_root.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(fixture)
    challenge_source_sha = _deep_audit_io.digest(challenge_inventory)
    config_path = baseline_path
    if challenge["kind"] == "mutation":
        mutation_hashes = lane.get("mutation_config_sha256")
        expected_mutation = (
            mutation_hashes.get(obligation["detector_rule_id"])
            if isinstance(mutation_hashes, dict)
            else None
        )
        mutated_config = _deep_audit_io._gitleaks_disable_rule(
            baseline, obligation["detector_rule_id"]
        )
        if (
            not isinstance(expected_mutation, str)
            or _deep_audit_io.sha256_bytes(mutated_config) != expected_mutation
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_GITLEAKS_MUTATION_BINDING", "signed mutation config digest differs"
            )
        config_path = case / "mutation.toml"
        config_path.write_bytes(mutated_config)
    scratch = case / "run"
    report_path, ledger_path = scratch / "report.sarif", scratch / "rule-ledger.json"
    argv_bindings = {
        "source": str(challenge_root),
        "output": str(scratch),
        "report": str(report_path),
        "scratch": str(scratch),
        "candidate_sha256": challenge_source_sha,
        "factory_ledger": str(ledger_path),
        "config": str(config_path),
    }

    def report_parser(raw):
        return _deep_audit_io._gitleaks_challenge_report(
            raw, profile, challenge_root, challenge_inventory
        )

    image = lane["image"]
    execution_bindings = {
        "candidate_sha256": contract["inventory"]["candidate_sha256"],
        "challenge_source_sha256": challenge_source_sha,
        "profile_sha256": _deep_audit_io.digest(profile),
        "image_sha256": common_sha256(image.encode("utf-8")),
        "tool_version": profile["tool_version"],
        "version_probe_sha256": _deep_audit_io.digest(execution["version_probe"]),
        "version_probe_facts": execution["version_probe"],
    }
    options = {}
    if "fixture_manifest" in challenge:
        options = {
            "native_artifact_roles": lane["native_artifact_roles"],
            "native_artifacts": {
                "sarif_report": report_path,
                "gitleaks_rule_ledger": ledger_path,
            },
            "rule_ids": lane["rule_ids"],
            "mutation_ruleset_sha256": lane["mutation_config_sha256"],
        }
    return execute(
        challenge,
        obligation_id=obligation["id"],
        engine="gitleaks",
        detector_rule_id=obligation["detector_rule_id"],
        detector_enabled=challenge["kind"] != "mutation",
        profile_argv=command["argv"],
        bindings=argv_bindings,
        source_root=challenge_root,
        baseline_config_path=baseline_path,
        effective_config_path=config_path,
        report_path=report_path,
        ledger_path=ledger_path,
        scratch=scratch,
        scratch_parent=case,
        timeout_seconds=timeout,
        expected_ruleset_sha256=lane["ruleset_sha256"],
        execution_bindings=execution_bindings,
        runner=runner,
        report_parser=report_parser,
        config_rule_ids=_deep_audit_io._gitleaks_rule_ids,
        verify_mutation=_deep_audit_io._gitleaks_mutation_valid,
        **options,
    )


def _gitleaks_challenge_report(raw, profile, source_root, sources):
    report = _deep_audit_io.strict_json(raw)
    if not isinstance(report, dict):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CHALLENGE_REPORT", "native report object required"
        )
    report = _deep_audit_io._native_sarif_metadata(report, profile, [])
    _deep_audit_io._normalize_challenge_sarif_paths(report, source_root)
    return _deep_audit_io._native_sarif_paths(report, sources)
