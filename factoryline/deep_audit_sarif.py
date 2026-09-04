"""Strict SARIF subset with native identities and source-bound ordered flow evidence.

This parser does not verify signer authority, execute scanners, or decide release.
Unrecognized SARIF indirection is rejected rather than silently dropping evidence.
"""
from __future__ import annotations

from pathlib import Path

from .deep_audit_io import bound_bytes, digest, relative_path, strict_json
from .runtime_audit_common import RuntimeAuditError, require_digest, require_int, require_str


def _list(value: object, minimum: int, maximum: int) -> list:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise RuntimeAuditError("E_SARIF_SHAPE", "array outside declared bounds")
    return value


def _object(value: object) -> dict:
    if not isinstance(value, dict):
        raise RuntimeAuditError("E_SARIF_SHAPE", "object required")
    return value


def _enum(value: object, choices: set[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise RuntimeAuditError("E_SARIF_ENUM", "unsupported SARIF enum")
    return value


def _location(value: object, sources: dict) -> dict:
    physical = _object(_object(value).get("physicalLocation"))
    artifact = _object(physical.get("artifactLocation"))
    if "uriBaseId" in artifact or "index" in artifact:
        raise RuntimeAuditError("E_SARIF_INDIRECTION", "expand artifact references before ingestion")
    path = relative_path(artifact.get("uri"))
    if path not in sources:
        raise RuntimeAuditError("E_TRACE_UNBOUND", "location has no source binding")
    region = _object(physical.get("region"))
    line = require_int(region.get("startLine"), "startLine", minimum=1, maximum=10_000_000)
    end = require_int(region.get("endLine", line), "endLine", minimum=line, maximum=10_000_000)
    column = require_int(region.get("startColumn", 1), "startColumn", minimum=1, maximum=10_000_000)
    end_column = require_int(region.get("endColumn", column), "endColumn", minimum=1, maximum=10_000_000)
    if end == line and end_column < column:
        raise RuntimeAuditError("E_SARIF_SHAPE", "reversed columns")
    return {"path": path, "source_sha256": sources[path], "start_line": line, "end_line": end,
            "start_column": column, "end_column": end_column}


def _flows(result: dict, sources: dict) -> list:
    flows = []
    total = 0
    for flow in _list(result.get("codeFlows", []), 0, 16):
        for thread in _list(_object(flow).get("threadFlows"), 1, 16):
            steps = []
            for step in _list(_object(thread).get("locations"), 1, 128):
                step = _object(step)
                if "index" in step:
                    raise RuntimeAuditError("E_SARIF_INDIRECTION", "expand thread locations before ingestion")
                kinds = _list(step.get("kinds", []), 0, 16)
                kinds = sorted({require_str(kind, "kind", maximum=128) for kind in kinds})
                steps.append({**_location(step.get("location"), sources), "kinds": kinds})
                total += 1
                if total > 128:
                    raise RuntimeAuditError("E_TRACE_LIMIT", "finding exceeds 128 flow steps")
            flows.append(steps)
    return flows


def _native(result: dict) -> dict:
    native = {}
    for group in ("partialFingerprints", "fingerprints"):
        for key, value in _object(result.get(group, {})).items():
            name = require_str(key, "fingerprint key", maximum=128)
            native[group + ":" + name] = require_str(value, "fingerprint", maximum=1024)
    if not 1 <= len(native) <= 16:
        raise RuntimeAuditError("E_NATIVE_FINGERPRINT", "require 1..16 native fingerprints")
    return native


def _suppression(result: dict) -> list:
    output = []
    for value in _list(result.get("suppressions", []), 0, 16):
        item = _object(value)
        output.append({"kind": _enum(item.get("kind"), {"inSource", "external"}),
                       "status": _enum(item.get("status", "underReview"), {"accepted", "underReview", "rejected"})})
    return sorted(output, key=lambda item: (item["kind"], item["status"]))


def _finding(result: object, analyzer: dict, sources: dict) -> dict:
    result = _object(result)
    if "rule" in result:
        raise RuntimeAuditError("E_SARIF_INDIRECTION", "expand rule references before ingestion")
    rule = require_str(result.get("ruleId"), "ruleId")
    native = _native(result)
    flows = _flows(result, sources)
    locations = [_location(item, sources) for item in _list(result.get("locations"), 1, 10)]
    suppressions = _suppression(result)
    return {
        "finding_id": digest({"schema": "factory.deep-finding-identity.v1", "analyzer": analyzer["id"], "rule": rule, "native": native}),
        "native_fingerprint_sha256": digest(native), "rule_id": rule,
        "analyzer_id": analyzer["id"],
        "kind": _enum(result.get("kind", "fail"), {"notApplicable", "pass", "fail", "review", "open", "informational"}),
        "level": _enum(result.get("level", "warning"), {"none", "note", "warning", "error"}),
        "baseline": _enum(result.get("baselineState", "unbaselined"), {"new", "updated", "unchanged", "absent", "unbaselined"}),
        "locations": locations, "flows": flows,
        "trace_sha256": digest({"locations": locations, "flows": flows}),
        "trace_depth": max((len(flow) for flow in flows), default=0),
        "suppressions": suppressions,
        "suppressed": any(item["status"] != "rejected" for item in suppressions),
    }


def _completed(run: dict, analyzer: dict) -> None:
    tool = _object(run.get("tool"))
    driver = _object(tool.get("driver"))
    if tool.get("extensions") or run.get("externalPropertyFileReferences"):
        raise RuntimeAuditError("E_SARIF_INDIRECTION", "external tool/property references unsupported")
    if driver.get("name") != analyzer["driver"] or driver.get("version") != analyzer["version"]:
        raise RuntimeAuditError("E_ANALYZER_MISMATCH", "driver/version does not match declaration")
    for invocation in _list(run.get("invocations"), 1, 16):
        invocation = _object(invocation)
        if invocation.get("executionSuccessful") is not True:
            raise RuntimeAuditError("E_ANALYZER_INCOMPLETE", "analyzer completion missing or false")
        for key in ("toolExecutionNotifications", "toolConfigurationNotifications"):
            for notification in _list(invocation.get(key, []), 0, 128):
                if _enum(_object(notification).get("level", "warning"), {"none", "note", "warning", "error"}) == "error":
                    raise RuntimeAuditError("E_ANALYZER_INCOMPLETE", "analyzer reported error notification")


def _check_rule_indices(run: dict, results: list) -> None:
    rules = _list(run["tool"]["driver"].get("rules", []), 0, 20_000)
    ids = [require_str(_object(rule).get("id"), "rule id") for rule in rules]
    if len(set(ids)) != len(ids):
        raise RuntimeAuditError("E_DUPLICATE_RULE", "duplicate driver rule ids")
    defaults = {rule["id"]: _object(rule.get("defaultConfiguration", {})).get("level", "warning") for rule in rules}
    for result in results:
        result = _object(result)
        if "ruleIndex" in result:
            index = require_int(result["ruleIndex"], "ruleIndex", minimum=0, maximum=max(0, len(ids)-1))
            if not ids or ids[index] != result.get("ruleId"):
                raise RuntimeAuditError("E_SARIF_INDIRECTION", "rule index/id mismatch")
        if "level" not in result:
            result["level"] = defaults.get(result.get("ruleId"), "warning")


def normalize_sarif(root: Path, binding: dict, analyzer: dict, source_hashes: dict) -> dict:
    """Normalize one hash-bound SARIF report with explicit analyzer identity and verified local source locations."""
    for key in ("id", "driver", "version"):
        require_str(analyzer.get(key), key)
    if not isinstance(source_hashes, dict) or not 1 <= len(source_hashes) <= 128:
        raise RuntimeAuditError("E_TRACE_UNBOUND", "require 1..128 source bindings")
    for path, value in source_hashes.items():
        relative_path(path)
        require_digest(value, "source_sha256")
        bound_bytes(root, {"path": path, "sha256": value})
    report = strict_json(bound_bytes(root, binding))
    if report.get("version") != "2.1.0":
        raise RuntimeAuditError("E_SARIF_VERSION", "require SARIF 2.1.0")
    run = _object(_list(report.get("runs"), 1, 1)[0])
    _completed(run, analyzer)
    results = _list(run.get("results"), 0, 20_000)
    _check_rule_indices(run, results)
    findings = [_finding(item, analyzer, source_hashes) for item in results]
    identities = [item["finding_id"] for item in findings]
    if len(identities) != len(set(identities)):
        raise RuntimeAuditError("E_DUPLICATE_FINDING", "native finding identity collision")
    for path, value in source_hashes.items():
        bound_bytes(root, {"path": path, "sha256": value})
    bound_bytes(root, binding)
    result = {"schema": "factory.deep-sarif.v1", "analyzer": {key: analyzer[key] for key in ("id", "driver", "version")},
              "report_sha256": binding["sha256"], "findings": sorted(findings, key=lambda item: item["finding_id"]),
              "authority": "none"}
    return {**result, "normalized_sha256": digest(result)}
