"""Read a bounded JUnit report for Graph Ops without running tests.

Test runners may write ``.factory/test-reports/pytest.xml`` (for example,
``pytest --junitxml=.factory/test-reports/pytest.xml``). A report is an
observation supplied by the workspace. It is not bound to the current commit,
working tree, interpreter, or environment and cannot certify that tests pass.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
from os import fstat
from pathlib import Path
from xml.etree import ElementTree


REPORT_PATH = Path(".factory/test-reports/pytest.xml")
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_CASES = 10_000
MAX_XML_DEPTH = 64


class _DepthLimitError(ValueError):
    """Raised when a report exceeds the bounded XML nesting depth."""


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
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def test_report_snapshot(root: Path) -> dict:
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
                if suite_names:
                    suite_names.pop()
                element.clear()
            depth -= 1
    except (_DepthLimitError, ElementTree.ParseError, ValueError) as exc:
        snapshot.update(
            state="INCOMPLETE",
            counts={"passed": 0, "failed": 0, "error": 0, "skipped": 0},
            total_count=0,
            cases=[],
            truncated=False,
            reason=(
                "The XML nesting depth exceeds the limit."
                if isinstance(exc, _DepthLimitError)
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
