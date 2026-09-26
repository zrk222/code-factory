"""Read-only repair comparisons and graph lineage; attestations grant no authority."""

from __future__ import annotations

from datetime import datetime, timezone
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


def _latest_run(root: Path) -> tuple[str, str] | None:
    directory = root
    for part in (".factory", "deep-runs"):
        directory /= part
        try:
            info = directory.lstat()
        except FileNotFoundError:
            return None
        if (
            not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("linked or invalid deep-run history")
    entries = list(islice(directory.iterdir(), 129))
    if len(entries) > 128:
        raise ValueError("deep-run history exceeds inspection bound")
    runs: list[tuple[int, str, str]] = []
    for path in entries:
        info = path.lstat()
        if (
            len(path.name) != 32
            or any(char not in "0123456789abcdef" for char in path.name)
            or not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("invalid deep-run entry")
        state_info = (path / "state.json").lstat()
        if (
            not stat.S_ISREG(state_info.st_mode)
            or getattr(state_info, "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("invalid deep-run state")
        source = f".factory/deep-runs/{path.name}/state.json"
        runs.append((state_info.st_mtime_ns, path.name, source))
    if not runs:
        return None
    _, run_id, source = max(runs)
    return run_id, source


def _run_details(run: dict[str, Any]) -> dict[str, Any]:
    lanes, gaps = run.get("lanes"), run.get("gaps")
    if (
        not isinstance(lanes, list)
        or len(lanes) > 32
        or not isinstance(gaps, list)
        or len(gaps) > 256
    ):
        raise ValueError("deep-run summary exceeds UI inspection bound")
    lane_summaries: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    repairs: list[dict[str, Any]] = []
    finding_count = 0
    coverage_gap_count = 0
    for gap in gaps:
        if not isinstance(gap, dict):
            raise ValueError("invalid deep-run coverage gap")
        coverage_gap_count += 1
        if len(coverage_gaps) < 20:
            coverage_gaps.append(
                {
                    "code": _label(gap.get("code"), "UNKNOWN_GAP"),
                    "path": _label(gap.get("path"), "."),
                    "action": _label(gap.get("action"), "Inspect the run and retry."),
                }
            )
    for lane in lanes:
        if (
            not isinstance(lane, dict)
            or not isinstance(lane.get("findings"), list)
            or not isinstance(lane.get("gaps"), list)
        ):
            raise ValueError("invalid deep-run lane")
        lane_id = _label(lane.get("lane_id"), "unknown")
        lane_summaries.append(
            {
                "lane_id": lane_id,
                "state": _label(lane.get("state"), "INCOMPLETE"),
                "finding_count": len(lane["findings"]),
                "gaps": [_label(code, "UNKNOWN_GAP") for code in lane["gaps"][:20]],
            }
        )
        coverage_gap_count += len(lane["gaps"])
        for code in lane["gaps"]:
            if len(coverage_gaps) < 20:
                coverage_gaps.append(
                    {
                        "code": _label(code, "UNKNOWN_GAP"),
                        "path": lane_id,
                        "action": "Resolve the analyzer prerequisite and rerun the signed scan.",
                    }
                )
        finding_count += len(lane["findings"])
        for finding in lane["findings"]:
            if not isinstance(finding, dict):
                raise ValueError("invalid deep-run finding")
            if len(repairs) < 20:
                repairs.append(
                    {
                        "finding_id": _label(finding.get("finding_id"), "unknown"),
                        "rule_id": _label(finding.get("rule_id"), "unknown"),
                        "severity": _label(finding.get("severity"), "unknown"),
                        "path": _label(finding.get("path"), "unknown"),
                        "line": finding.get("line")
                        if type(finding.get("line")) is int
                        else None,
                        "source_sha256": finding.get("source_sha256"),
                        "remediation": _label(
                            finding.get("remediation"), "Inspect and repair this finding."
                        ),
                    }
                )
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


def _case(element: ElementTree.Element, suite_name: str) -> dict:
    markers = {_local_tag(child.tag): child for child in element}
    if "error" in markers:
        status, result = "error", markers["error"]
    elif "failure" in markers:
        status, result = "failed", markers["failure"]
    elif "skipped" in markers:
        status, result = "skipped", markers["skipped"]
    else:
        declared_status = str(element.get("status") or "").lower()
        status = declared_status if declared_status in {"failed", "error", "skipped"} else "passed"
        result = None
    failure_summary = None
    if result is not None:
        failure_summary = _bounded(result.get("message") or result.text, 400) or None
    return {
        "suite": _bounded(element.get("classname") or suite_name, 240),
        "name": _bounded(element.get("name"), 300),
        "status": status,
        "file": _bounded(element.get("file"), 500) or None,
        "line": _line(element.get("line")),
        "duration_seconds": _duration(element.get("time")),
        "failure_summary": failure_summary,
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


def read_junit_report(root: Path) -> dict:
    """Read one local JUnit XML report and retain every case within limits.

    ``INCOMPLETE`` means the report is unreadable, malformed, inconsistent, or
    exceeds a stated limit. The function never executes code or follows a
    report path outside the resolved workspace. Case metadata is untrusted.
    """
    snapshot = _base_snapshot()
    try:
        workspace = root.resolve()
        source = (workspace / REPORT_PATH).resolve()
        source.relative_to(workspace)
    except (OSError, RuntimeError, ValueError):
        snapshot.update(state="INCOMPLETE", reason="The report path escapes the workspace or cannot be resolved.")
        return snapshot

    try:
        if not source.exists():
            return snapshot
        if not source.is_file():
            snapshot.update(state="INCOMPLETE", reason="The report path is not a regular file.")
            return snapshot
        with source.open("rb") as handle:
            content = handle.read(MAX_REPORT_BYTES + 1)
            metadata = fstat(handle.fileno())
    except OSError:
        snapshot.update(state="INCOMPLETE", reason="The report could not be read.")
        return snapshot

    snapshot["source_mtime_utc"] = datetime.fromtimestamp(
        metadata.st_mtime, timezone.utc
    ).isoformat().replace("+00:00", "Z")
    if len(content) > MAX_REPORT_BYTES:
        snapshot.update(
            state="INCOMPLETE",
            truncated=True,
            reason="The report exceeds the byte limit; no partial file was parsed.",
        )
        return snapshot
    snapshot["source_sha256"] = sha256(content).hexdigest()
    try:
        content.decode("utf-8-sig")
    except UnicodeError:
        snapshot.update(state="INCOMPLETE", reason="The XML report must be UTF-8 encoded.")
        return snapshot
    if b"\x00" in content:
        snapshot.update(state="INCOMPLETE", reason="The XML report contains NUL bytes.")
        return snapshot
    if b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
        snapshot.update(state="INCOMPLETE", reason="XML declarations with entities or DTDs are not accepted.")
        return snapshot

    depth = 0
    suite_names: list[str] = []
    suite_checks: list[tuple[int, dict[str, int], dict[str, int | None]]] = []
    declared: int | None = None
    declared_results: dict[str, int] = {}
    root_tag: str | None = None
    try:
        for event, element in ElementTree.iterparse(BytesIO(content), events=("start", "end")):
            tag = _local_tag(element.tag)
            if event == "start":
                depth += 1
                if depth > MAX_XML_DEPTH:
                    raise _DepthLimitError
                if depth == 1:
                    root_tag = tag
                    declared = _declared_count(element.get("tests"))
                    for attribute, status in (
                        ("failures", "failed"),
                        ("errors", "error"),
                        ("skipped", "skipped"),
                    ):
                        count = _declared_count(element.get(attribute))
                        if count is not None:
                            declared_results[status] = count
                    snapshot["report_time"] = _bounded(element.get("timestamp"), 80) or None
                if tag == "testsuite":
                    suite_names.append(_bounded(element.get("name"), 240))
                    suite_checks.append(
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
                continue
            if tag == "testcase":
                case = _case(element, suite_names[-1] if suite_names else "")
                snapshot["counts"][case["status"]] += 1
                snapshot["total_count"] += 1
                if len(snapshot["cases"]) < MAX_CASES:
                    snapshot["cases"].append(case)
                else:
                    snapshot["truncated"] = True
                element.clear()
            elif tag == "testsuite":
                before_total, before_counts, suite_declared = suite_checks.pop()
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
                if suite_names:
                    suite_names.pop()
                element.clear()
            depth -= 1
    except (_DepthLimitError, _CountMismatch, ElementTree.ParseError, ValueError) as exc:
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
                else "The XML report is malformed."
            ),
        )
        return snapshot

    if root_tag not in {"testsuite", "testsuites"}:
        snapshot.update(state="INCOMPLETE", reason="The XML root is not a JUnit testsuite or testsuites element.")
    elif snapshot["truncated"]:
        snapshot.update(state="INCOMPLETE", reason="Some cases exceed the display limit; the complete count remains visible.")
    elif declared is not None and declared != snapshot["total_count"]:
        snapshot.update(state="INCOMPLETE", reason="The declared test count differs from parsed test cases.")
    elif any(snapshot["counts"][status] != count for status, count in declared_results.items()):
        snapshot.update(state="INCOMPLETE", reason="Declared test outcomes differ from parsed case outcomes.")
    else:
        snapshot.update(
            state="OBSERVED",
            reason="Report cases were read; this report is not bound to the current candidate.",
        )
    return snapshot
