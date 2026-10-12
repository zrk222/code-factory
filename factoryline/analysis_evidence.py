"""Vendor-neutral, deterministic SARIF evidence adapter.

The adapter reads a user-selected local SARIF artifact. It never starts an
analyzer, contacts a vendor, modifies source, or treats a report as approval.
"""

from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import unquote, urlparse

from .runtime_audit_common import canonical_bytes


SCHEMA = "factory.analysis-evidence.v1"
MAX_ARTIFACT_BYTES = 10_000_000
SUPPORTED_PROVIDERS = ("qodana", "sonarqube")
_PROVIDER_NAMES = {
    "qodana": ("qodana",),
    "sonarqube": ("sonarqube", "sonarlint", "sonar"),
}
REVIEW_EVIDENCE_SCHEMA = "factory.review-evidence.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVIEW_LIMIT = 20_000


class AnalysisEvidenceError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return canonical_bytes(value)


def _review_digest(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _review_id(kind: str, value: object) -> str:
    return f"{kind}:{_review_digest(value)}"


def _is_sha(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _review_context(receipt, plan, internal_hash):
    if not isinstance(receipt, Mapping):
        raise AnalysisEvidenceError(
            "REVIEW_EVIDENCE_INVALID", "receipt must be an object"
        )
    candidate = receipt.get("candidate_sha256")
    receipt_sha = receipt.get("receipt_sha256", internal_hash)
    if not _is_sha(candidate) or not _is_sha(receipt_sha):
        raise AnalysisEvidenceError(
            "REVIEW_EVIDENCE_INVALID", "candidate and receipt hashes must be SHA-256"
        )
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if "receipt_sha256" in receipt and _review_digest(body) != receipt_sha:
        raise AnalysisEvidenceError(
            "REVIEW_EVIDENCE_INVALID", "receipt hash does not match its contents"
        )
    if (
        plan is not None
        and receipt.get("plan_payload_sha256") is not None
        and _review_digest(plan) != receipt.get("plan_payload_sha256")
    ):
        raise AnalysisEvidenceError(
            "REVIEW_EVIDENCE_INVALID", "review plan does not match the receipt binding"
        )
    lanes = receipt.get("lanes", [])
    lanes = lanes if isinstance(lanes, list) else []
    definitions = {
        item.get("id"): item
        for item in (plan or {}).get("lanes", [])
        if isinstance(item, Mapping)
    }
    findings = receipt.get("findings", []) or _lane_findings(lanes, definitions)
    hashes = receipt.get("report_hashes", {}) or _lane_report_hashes(lanes, definitions)
    if (
        not isinstance(findings, list)
        or len(findings) > _REVIEW_LIMIT
        or not isinstance(hashes, Mapping)
    ):
        raise AnalysisEvidenceError(
            "REVIEW_EVIDENCE_INVALID",
            "receipt evidence exceeds bounds or has invalid shape",
        )
    return candidate, receipt_sha, lanes, findings, hashes, definitions


def _lane_findings(lanes, definitions):
    rows = []
    for lane in lanes:
        if not isinstance(lane, Mapping):
            continue
        lane_id = lane.get("lane_id")
        engine = lane.get("engine", definitions.get(lane_id, {}).get("engine"))
        for finding in lane.get("findings", []):
            if isinstance(finding, Mapping):
                rows.append(
                    {
                        **finding,
                        "analyzer_id": engine,
                        "finding_id": finding.get("finding_id")
                        or _review_id("finding", {"lane": lane_id, "finding": finding}),
                    }
                )
    return rows


def _lane_report_hashes(lanes, definitions):
    rows = {}
    for lane in lanes:
        if not isinstance(lane, Mapping):
            continue
        lane_id = lane.get("lane_id")
        engine = lane.get("engine", definitions.get(lane_id, {}).get("engine"))
        if isinstance(engine, str) and isinstance(lane.get("report_sha256"), str):
            rows[engine] = lane["report_sha256"]
    return rows


def _lane_projection(lanes, candidate):
    evidence, unknowns = [], []
    for lane in lanes:
        if not isinstance(lane, Mapping) or not isinstance(lane.get("lane_id"), str):
            continue
        lane_id = lane["lane_id"]
        evidence.append(
            {
                "id": _review_id(
                    "lane",
                    {
                        key: lane.get(key)
                        for key in ("lane_id", "report_sha256", "coverage_sha256")
                    },
                ),
                "kind": "lane_observation",
                "epistemic_status": "observed",
                "provenance": {
                    "lane_id": lane_id,
                    "state": lane.get("state"),
                    "gaps": lane.get("gaps", []),
                    "report_sha256": lane.get("report_sha256"),
                    "coverage_sha256": lane.get("coverage_sha256"),
                    "native_execution": lane.get("native_execution"),
                    "execution": lane.get("execution"),
                    "candidate_sha256": candidate,
                },
            }
        )
        if lane.get("state") != "OBSERVED" or lane.get("gaps"):
            unknowns.append(
                {
                    "id": _review_id("lane_gap", lane_id),
                    "verification_action": (
                        f"Resolve lane {lane_id} gaps and rerun it against the exact candidate."
                    ),
                }
            )
        if not _is_sha(lane.get("report_sha256")) or not _is_sha(
            lane.get("coverage_sha256")
        ):
            unknowns.append(
                {
                    "id": _review_id("lane_hash", lane_id),
                    "verification_action": (
                        f"Retain report and coverage hashes for lane {lane_id} before reuse."
                    ),
                }
            )
    return evidence, unknowns


def _report_projection(hashes, reports, expected, receipt_sha):
    rows = {
        item.get("analyzer", {}).get("id"): item
        for item in (reports or [])
        if isinstance(item, Mapping) and isinstance(item.get("analyzer"), Mapping)
    }
    evidence, unknowns = [], []
    for analyzer, report_hash in sorted(hashes.items()):
        if not isinstance(analyzer, str) or not _is_sha(report_hash):
            raise AnalysisEvidenceError(
                "REVIEW_EVIDENCE_INVALID", "report hash binding is invalid"
            )
        report = rows.get(analyzer)
        if report is not None:
            report_body = {
                key: value
                for key, value in report.items()
                if key != "normalized_sha256"
            }
            if (
                report.get("normalized_sha256") != report_hash
                or _review_digest(report_body) != report_hash
            ):
                raise AnalysisEvidenceError(
                    "REVIEW_EVIDENCE_INVALID",
                    "normalized report does not match the receipt report hash",
                )
        evidence.append(
            {
                "id": _review_id(
                    "report", {"analyzer": analyzer, "sha256": report_hash}
                ),
                "kind": "analyzer_report",
                "epistemic_status": "observed",
                "provenance": {
                    "analyzer_id": analyzer,
                    "report_sha256": report_hash,
                    "receipt_sha256": receipt_sha,
                    "execution_successful": report.get("execution_successful")
                    if report
                    else None,
                },
            }
        )
        if reports is not None and (report is None or analyzer not in expected):
            unknowns.append(
                {
                    "id": _review_id("missing_report_context", analyzer),
                    "verification_action": (
                        f"Verify analyzer {analyzer} identity and execution context against the signed audit plan."
                    ),
                }
            )
    return evidence, unknowns


def _source_match(candidate_sources, finding, paths):
    if not isinstance(candidate_sources, Mapping):
        return False
    location_hashes = {
        item.get("path"): item.get("source_sha256")
        for item in finding.get("locations", [])
        if isinstance(item, Mapping)
    }
    return all(
        _is_sha(candidate_sources.get(path))
        and candidate_sources[path] == location_hashes.get(path)
        for path in paths
    )


def _finding_projection(findings, hashes, receipt):
    evidence, claims, unknowns = [], [], []
    for finding in findings:
        if not isinstance(finding, Mapping):
            raise AnalysisEvidenceError(
                "REVIEW_EVIDENCE_INVALID", "finding must be an object"
            )
        analyzer, fid = finding.get("analyzer_id"), finding.get("finding_id")
        if (
            not isinstance(analyzer, str)
            or not isinstance(fid, str)
            or not fid
            or len(fid) > 256
        ):
            raise AnalysisEvidenceError(
                "REVIEW_EVIDENCE_INVALID", "finding identity is invalid"
            )
        report_hash = hashes.get(analyzer)
        if not _is_sha(report_hash):
            unknowns.append(
                {
                    "id": _review_id("finding_provenance", fid),
                    "verification_action": (
                        f"Bind finding {fid} to an exact analyzer report hash before relying on it."
                    ),
                }
            )
            continue
        evidence_id = _review_id(
            "finding", {"finding_id": fid, "report_sha256": report_hash}
        )
        details = {
            key: finding.get(key)
            for key in (
                "rule_id",
                "kind",
                "level",
                "baseline",
                "suppressed",
                "suppressions",
                "flows",
                "locations",
                "source_sha256",
            )
        }
        evidence.append(
            {
                "id": evidence_id,
                "kind": "sarif_finding",
                "epistemic_status": "observed",
                "provenance": {
                    "analyzer_id": analyzer,
                    "finding_id": fid,
                    "report_sha256": report_hash,
                    "report_evidence_id": _review_id(
                        "report", {"analyzer": analyzer, "sha256": report_hash}
                    ),
                    **details,
                },
            }
        )
        paths = [
            item.get("path")
            for item in finding.get("locations", [])
            if isinstance(item, Mapping) and isinstance(item.get("path"), str)
        ]
        statement = (
            f"Analyzer {analyzer} reported rule {finding.get('rule_id', 'unknown')} "
            f"with kind {finding.get('kind', 'fail')} at "
            f"{', '.join(paths) if paths else 'no normalized source location'}. "
            "This is a reported analyzer fact, not a confirmed defect."
        )
        claims.append(
            {
                "id": _review_id("claim", fid),
                "statement": statement[:500],
                "supporting_evidence_ids": [evidence_id],
                "contradicting_evidence_ids": [],
                "status": "supported",
            }
        )
        if paths and not _source_match(
            receipt.get("source_hashes", {}), finding, paths
        ):
            unknowns.append(
                {
                    "id": _review_id("source_link", fid),
                    "verification_action": (
                        f"Reconcile finding {fid} locations and source digest "
                        "with exact candidate source hashes."
                    ),
                }
            )
    return evidence, claims, unknowns


def _coverage_unknowns(lanes, hashes, expected, plan, receipt):
    unknowns = []
    for gap in receipt.get("gaps", []):
        label = (
            gap.get("code", "unclassified") if isinstance(gap, Mapping) else str(gap)
        )
        unknowns.append(
            {
                "id": _review_id("execution_gap", gap),
                "verification_action": f"Resolve execution gap {label} and rerun the affected analysis against the exact candidate.",
            }
        )
    expected_count = len(plan.get("lanes", [])) if plan else len(expected)
    if (
        (lanes and len(lanes) != 6)
        or (not lanes and len(hashes) < 6)
        or (expected_count and expected_count != 6)
    ):
        unknowns.append(
            {
                "id": _review_id(
                    "six_lane_coverage",
                    {"reports": sorted(hashes), "expected": sorted(expected)},
                ),
                "verification_action": "Verify six distinct required audit lanes and their candidate-bound reports; report presence alone does not establish six-lane coverage.",
            }
        )
    runtime = any(
        isinstance(lane, Mapping)
        and lane.get("family") in {"runtime", "fuzz"}
        and lane.get("state") == "OBSERVED"
        and _is_sha(lane.get("report_sha256"))
        and _is_sha(lane.get("coverage_sha256"))
        and isinstance(lane.get("native_execution"), Mapping)
        and lane["native_execution"].get("source_candidate_sha256")
        == receipt.get("candidate_sha256")
        and lane["native_execution"].get("cleanup_confirmed") is True
        for lane in lanes
    )
    if not runtime:
        unknowns.append(
            {
                "id": _review_id("runtime_evidence", receipt.get("candidate_sha256")),
                "verification_action": "Obtain and verify candidate-bound runtime evidence before making runtime behavior claims.",
            }
        )
    return unknowns


def _build_review_evidence(receipt, *, reports=None, plan=None, _receipt_sha256=None):
    candidate, receipt_sha, lanes, findings, hashes, _ = _review_context(
        receipt, plan, _receipt_sha256
    )
    lane_rows, lane_unknowns = _lane_projection(lanes, candidate)
    expected = {
        item.get("id")
        for item in (plan or {}).get("analyzers", [])
        if isinstance(item, Mapping)
    }
    expected.update(
        item.get("engine")
        for item in (plan or {}).get("lanes", [])
        if isinstance(item, Mapping)
    )
    report_rows, report_unknowns = _report_projection(
        hashes, reports, expected, receipt_sha
    )
    finding_rows, claims, finding_unknowns = _finding_projection(
        findings, hashes, receipt
    )
    unknowns = (
        lane_unknowns
        + report_unknowns
        + finding_unknowns
        + _coverage_unknowns(lanes, hashes, expected, plan, receipt)
    )
    core = {
        "schema": REVIEW_EVIDENCE_SCHEMA,
        "candidate_sha256": candidate,
        "receipt_sha256": receipt_sha,
        "evidence": lane_rows
        + report_rows
        + finding_rows
        + (
            [
                {
                    "id": _review_id(
                        "execution_summary",
                        {
                            key: receipt.get(key)
                            for key in (
                                "run_id",
                                "state",
                                "analysis_complete",
                                "pause_requested",
                                "review",
                                "gaps",
                            )
                        },
                    ),
                    "kind": "execution_summary",
                    "epistemic_status": "observed",
                    "provenance": {
                        key: receipt.get(key)
                        for key in (
                            "run_id",
                            "state",
                            "analysis_complete",
                            "pause_requested",
                            "review",
                            "gaps",
                        )
                    },
                }
            ]
            if lanes
            else []
        ),
        "claims": claims,
        "unknowns": unknowns,
        "authority": "none",
    }
    return {**core, "packet_sha256": _review_digest(core)}


def build_review_evidence(
    receipt: Mapping[str, Any],
    *,
    reports: list[Mapping[str, Any]] | None = None,
    plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build from an internally self-hashed signed-audit evaluation receipt."""
    return _build_review_evidence(receipt, reports=reports, plan=plan)


def build_execution_review_evidence(
    state: Mapping[str, Any],
    plan: Mapping[str, Any],
    evidence_path: Path,
) -> dict[str, Any]:
    """Build from persisted six-lane state, bound to exact evidence.json bytes."""
    if not isinstance(state, Mapping):
        raise AnalysisEvidenceError(
            "REVIEW_EVIDENCE_INVALID", "execution state must be an object"
        )
    path = Path(evidence_path)
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_ARTIFACT_BYTES + 1)
        persisted = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AnalysisEvidenceError(
            "REVIEW_EVIDENCE_INVALID", "persisted execution evidence is unreadable"
        ) from exc
    if len(raw) > MAX_ARTIFACT_BYTES or not isinstance(persisted, Mapping):
        raise AnalysisEvidenceError(
            "REVIEW_EVIDENCE_INVALID", "persisted execution evidence exceeds bounds"
        )
    expected = {**state, "sha256": _review_digest(state)}
    if persisted != expected:
        raise AnalysisEvidenceError(
            "REVIEW_EVIDENCE_INVALID",
            "persisted execution state does not match returned state",
        )
    return _build_review_evidence(
        state, plan=plan, _receipt_sha256=sha256(raw).hexdigest()
    )


def _valid_evidence(item):
    return (
        isinstance(item, Mapping)
        and set(item) == {"id", "kind", "epistemic_status", "provenance"}
        and all(isinstance(item.get(key), str) and item[key] for key in ("id", "kind"))
        and item.get("epistemic_status") in {"observed", "inferred", "unknown"}
        and isinstance(item.get("provenance"), Mapping)
    )


def _valid_claim(item, evidence_ids):
    fields = {
        "id",
        "statement",
        "supporting_evidence_ids",
        "contradicting_evidence_ids",
        "status",
    }
    if (
        not isinstance(item, Mapping)
        or set(item) != fields
        or not isinstance(item.get("id"), str)
        or not isinstance(item.get("statement"), str)
        or not item["statement"].strip()
        or len(item["statement"]) > 500
        or item.get("status") not in {"supported", "contradicted", "unresolved"}
    ):
        return False
    support, contradiction = (
        item["supporting_evidence_ids"],
        item["contradicting_evidence_ids"],
    )
    refs_valid = all(
        isinstance(refs, list)
        and all(isinstance(ref, str) and ref in evidence_ids for ref in refs)
        and len(refs) == len(set(refs))
        for refs in (support, contradiction)
    )
    return (
        refs_valid
        and not (set(support) & set(contradiction))
        and (item["status"] != "supported" or bool(support))
        and (item["status"] != "contradicted" or bool(contradiction))
    )


def _valid_unknown(item):
    return (
        isinstance(item, Mapping)
        and set(item) == {"id", "verification_action"}
        and isinstance(item.get("id"), str)
        and isinstance(item.get("verification_action"), str)
        and bool(item["verification_action"].strip())
        and len(item["verification_action"]) <= 500
    )


def _unique_ids(rows, predicate, message):
    ids = set()
    for item in rows:
        if not predicate(item) or item["id"] in ids:
            raise AnalysisEvidenceError("REVIEW_EVIDENCE_INVALID", message)
        ids.add(item["id"])
    return ids


def validate_review_evidence(packet: Mapping[str, Any]) -> dict[str, Any]:
    """Validate packet structure, references, boundedness, and canonical self-hash."""
    fields = {
        "schema",
        "candidate_sha256",
        "receipt_sha256",
        "evidence",
        "claims",
        "unknowns",
        "authority",
        "packet_sha256",
    }
    if not isinstance(packet, Mapping) or set(packet) != fields:
        raise AnalysisEvidenceError(
            "REVIEW_EVIDENCE_INVALID",
            "packet fields do not match the review evidence schema",
        )
    core = {key: value for key, value in packet.items() if key != "packet_sha256"}
    hashes = ("candidate_sha256", "receipt_sha256", "packet_sha256")
    if (
        packet.get("schema") != REVIEW_EVIDENCE_SCHEMA
        or packet.get("authority") != "none"
        or not all(_is_sha(packet.get(key)) for key in hashes)
        or _review_digest(core) != packet.get("packet_sha256")
    ):
        raise AnalysisEvidenceError(
            "REVIEW_EVIDENCE_INVALID", "schema, authority, or packet hash is invalid"
        )
    evidence, claims, unknowns = (
        packet.get(key) for key in ("evidence", "claims", "unknowns")
    )
    if not all(
        isinstance(rows, list) and len(rows) <= _REVIEW_LIMIT
        for rows in (evidence, claims, unknowns)
    ):
        raise AnalysisEvidenceError(
            "REVIEW_EVIDENCE_INVALID",
            "packet arrays exceed bounds or have invalid shape",
        )
    evidence_ids = _unique_ids(
        evidence, _valid_evidence, "evidence item is invalid or duplicated"
    )
    _unique_ids(
        claims,
        lambda item: _valid_claim(item, evidence_ids),
        "claim is invalid or duplicated",
    )
    _unique_ids(
        unknowns,
        _valid_unknown,
        "unknown item needs a unique id and concrete verification action",
    )
    if len(_canonical(packet)) > MAX_ARTIFACT_BYTES:
        raise AnalysisEvidenceError(
            "REVIEW_EVIDENCE_INVALID", "packet exceeds byte bound"
        )
    return dict(packet)


def assess_review_reuse(
    packet: Mapping[str, Any],
    *,
    candidate_sha256: str,
    receipt_sha256: str,
    required_evidence_ids: list[str],
) -> dict[str, Any]:
    """Allow focused reuse only when all exact candidate/evidence bindings match."""
    try:
        checked = validate_review_evidence(packet)
    except AnalysisEvidenceError:
        return {
            "decision": "RERUN",
            "reason": "review evidence packet is invalid or tampered",
        }
    if checked["candidate_sha256"] != candidate_sha256:
        return {"decision": "RERUN", "reason": "candidate hash changed"}
    if checked["receipt_sha256"] != receipt_sha256:
        return {"decision": "RERUN", "reason": "receipt or bound tool profile changed"}
    if not isinstance(required_evidence_ids, list) or any(
        not isinstance(item, str) for item in required_evidence_ids
    ):
        return {
            "decision": "RERUN",
            "reason": "required evidence identifiers are invalid",
        }
    present = {item["id"] for item in checked["evidence"]}
    missing = sorted(set(required_evidence_ids) - present)
    if missing:
        return {
            "decision": "RERUN",
            "reason": "required evidence is missing",
            "missing_evidence_ids": missing,
        }
    return {
        "decision": "REUSE",
        "reason": "exact candidate, receipt, and required evidence hashes match",
    }


def _workspace(root: Path) -> Path:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise AnalysisEvidenceError(
            "ANALYSIS_ROOT_INVALID", "root must be an existing directory"
        )
    return workspace


def _local_file(workspace: Path, value: Path) -> Path:
    candidate = Path(value)
    candidate = (
        candidate.resolve()
        if candidate.is_absolute()
        else (workspace / candidate).resolve()
    )
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise AnalysisEvidenceError(
            "ANALYSIS_PATH_REJECTED", "analysis evidence must stay inside the workspace"
        ) from exc
    if not candidate.is_file() or candidate.stat().st_size > MAX_ARTIFACT_BYTES:
        raise AnalysisEvidenceError(
            "ANALYSIS_ARTIFACT_INVALID",
            f"analysis evidence must be a regular file no larger than {MAX_ARTIFACT_BYTES} bytes",
        )
    return candidate


def _driver_names(payload: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for run in payload.get("runs", []):
        if not isinstance(run, dict):
            continue
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        name = driver.get("name") if isinstance(driver, dict) else None
        if isinstance(name, str) and name.strip():
            names.append(name.strip())
    return sorted(set(names), key=str.casefold)


def _detected_provider(names: list[str]) -> str | None:
    detected: set[str] = set()
    for name in names:
        lowered = name.casefold()
        for provider, aliases in _PROVIDER_NAMES.items():
            if any(alias in lowered for alias in aliases):
                detected.add(provider)
    if len(detected) > 1:
        raise AnalysisEvidenceError(
            "ANALYSIS_PROVIDER_AMBIGUOUS",
            "SARIF tool drivers identify more than one supported provider",
        )
    return next(iter(detected), None)


def _provider(requested: str, names: list[str]) -> str:
    value = requested.strip().lower() if isinstance(requested, str) else ""
    if value not in {"auto", *SUPPORTED_PROVIDERS}:
        raise AnalysisEvidenceError(
            "ANALYSIS_PROVIDER_UNSUPPORTED",
            "analysis provider must be auto, qodana, or sonarqube",
        )
    detected = _detected_provider(names)
    if value == "auto":
        if detected is None:
            raise AnalysisEvidenceError(
                "ANALYSIS_PROVIDER_UNVERIFIED",
                "auto detection requires a Qodana or SonarQube SARIF tool driver name",
            )
        return detected
    if detected is not None and detected != value:
        raise AnalysisEvidenceError(
            "ANALYSIS_PROVIDER_MISMATCH",
            f"requested {value} but SARIF tool driver identifies {detected}",
        )
    return value


def _safe_uri(uri: object) -> str | None:
    if not isinstance(uri, str) or not uri.strip():
        return None
    decoded = unquote(uri.strip()).replace("\\", "/")
    parsed = urlparse(decoded)
    if (
        parsed.scheme
        or parsed.netloc
        or decoded.startswith("/")
        or re.match(r"^[A-Za-z]:/", decoded)
    ):
        return None
    normalized = decoded.removeprefix("./").rstrip("/")
    if not normalized or any(part in {"", ".."} for part in normalized.split("/")):
        return None
    return normalized


def _load_sarif_payload(raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AnalysisEvidenceError(
            "ANALYSIS_SARIF_INVALID", "analysis evidence must contain UTF-8 JSON"
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("version") != "2.1.0"
        or not isinstance(payload.get("runs"), list)
        or not payload["runs"]
    ):
        raise AnalysisEvidenceError(
            "ANALYSIS_SARIF_INVALID",
            "analysis evidence must be a SARIF 2.1.0 object with at least one run",
        )
    return payload


def _normalized_result_locations(result: dict[str, Any]) -> list[str]:
    raw_locations = result.get("locations", [])
    if not isinstance(raw_locations, list):
        raise AnalysisEvidenceError(
            "ANALYSIS_SARIF_INVALID", "SARIF result locations must be an array"
        )
    paths = []
    for location in raw_locations:
        try:
            uri = location["physicalLocation"]["artifactLocation"]["uri"]
        except (KeyError, TypeError):
            continue
        safe = _safe_uri(uri)
        if safe is not None:
            paths.append(safe)
    return sorted(set(paths))[:20]


def _normalized_sarif_result(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise AnalysisEvidenceError(
            "ANALYSIS_SARIF_INVALID", "SARIF results must be objects"
        )
    rule = result.get("ruleId")
    if not isinstance(rule, str) or not rule.strip() or len(rule) > 200:
        raise AnalysisEvidenceError(
            "ANALYSIS_SARIF_INVALID", "each SARIF result must contain a bounded ruleId"
        )
    level = result.get("level", "warning")
    if level not in {"error", "warning", "note", "none"}:
        raise AnalysisEvidenceError(
            "ANALYSIS_SARIF_INVALID", "SARIF result level is unsupported"
        )
    baseline = result.get("baselineState", "unbaselined")
    if baseline not in {"new", "unchanged", "absent", "updated", "unbaselined"}:
        raise AnalysisEvidenceError(
            "ANALYSIS_SARIF_INVALID", "SARIF baselineState is unsupported"
        )
    return {
        "rule_id": rule.strip(),
        "level": level,
        "baseline_state": baseline,
        "paths": _normalized_result_locations(result),
    }


def _normalized_sarif_run(run: Any) -> tuple[list[dict[str, Any]], list[bool]]:
    if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
        raise AnalysisEvidenceError(
            "ANALYSIS_SARIF_INVALID",
            "every SARIF run must contain a results array when present",
        )
    invocations = run.get("invocations", [])
    if not isinstance(invocations, list):
        raise AnalysisEvidenceError(
            "ANALYSIS_SARIF_INVALID", "SARIF invocations must be an array"
        )
    execution = [
        item["executionSuccessful"]
        for item in invocations
        if isinstance(item, dict) and isinstance(item.get("executionSuccessful"), bool)
    ]
    return [
        _normalized_sarif_result(item) for item in run.get("results", [])
    ], execution


def _sarif_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        key: 0
        for key in (
            "error",
            "warning",
            "note",
            "none",
            "new",
            "unchanged",
            "absent",
            "updated",
            "unbaselined",
        )
    }
    for finding in findings:
        counts[finding["level"]] += 1
        counts[finding["baseline_state"]] += 1
    return counts


def _execution_status(execution: list[bool]) -> bool | None:
    if False in execution:
        return False
    return True if execution else None


def _seal_evidence(core: dict[str, Any]) -> dict[str, Any]:
    core["evidence_sha256"] = sha256(
        json.dumps(
            core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    return core


def parse_analysis_sarif(
    root: Path, sarif_path: Path, *, provider: str = "auto"
) -> dict[str, Any]:
    """Normalize bounded Qodana or SonarQube SARIF facts without executing it."""
    workspace = _workspace(root)
    path = _local_file(workspace, sarif_path)
    raw = path.read_bytes()
    payload = _load_sarif_payload(raw)
    names = _driver_names(payload)
    resolved_provider = _provider(provider, names)
    findings: list[dict[str, Any]] = []
    execution: list[bool] = []
    for run in payload["runs"]:
        run_findings, run_execution = _normalized_sarif_run(run)
        findings.extend(run_findings)
        execution.extend(run_execution)
    core = {
        "schema": SCHEMA,
        "marker": "ANALYSIS_EVIDENCE_NORMALIZED",
        "provider": resolved_provider,
        "tool_driver_names": names,
        "path": path.relative_to(workspace).as_posix(),
        "file_sha256": sha256(raw).hexdigest(),
        "execution_successful": _execution_status(execution),
        "counts": _sarif_counts(findings),
        "findings": sorted(
            findings,
            key=lambda item: (
                item["baseline_state"],
                item["level"],
                item["rule_id"],
                item["paths"],
            ),
        ),
        "authority": {
            "analyzer_execute": False,
            "source_modify": False,
            "network": False,
            "approval": False,
        },
        "claim_boundary": "supplied local SARIF facts only; not analyzer execution, vendor certification, absence of defects, or release approval",
    }
    return _seal_evidence(core)
