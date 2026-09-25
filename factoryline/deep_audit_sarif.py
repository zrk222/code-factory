"""Strict SARIF subset with native identities and source-bound ordered flow evidence.

This parser does not verify signer authority, execute scanners, or decide release.
Unrecognized SARIF indirection is rejected rather than silently dropping evidence.
"""

from __future__ import annotations

from pathlib import Path
import re

from .deep_audit_io import bound_bytes, digest, relative_path, strict_json
from .runtime_audit_common import (
    RuntimeAuditError,
    require_digest,
    require_int,
    require_str,
)


def _safe_text(value: object, maximum: int = 2048) -> str:
    text = require_str(value, "display text", maximum=maximum)
    text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text)
    return "".join(
        char
        for char in text
        if char.isprintable()
        and char
        not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200b\u200c\u200d\ufeff"
    )


def _execution_finding(
    lane: dict,
    rule: object,
    path: object,
    line: object,
    severity: object,
    sources: dict,
    *,
    flows: list | None = None,
    suppressed: bool = False,
) -> dict:
    rule = _safe_text(rule, 256)
    path = relative_path(path)
    if path not in sources:
        raise RuntimeAuditError(
            "E_TRACE_UNBOUND", "finding path is outside the candidate"
        )
    line = require_int(line, "line", minimum=1, maximum=10_000_000)
    severity = str(severity).lower()
    severity = {"error": "high", "warning": "medium", "note": "low"}.get(
        severity, severity
    )
    if severity not in {"critical", "high", "medium", "low"}:
        severity = "high"  # Unknown severity cannot lower priority.
    return {
        "finding_id": digest(
            {"engine": lane["engine"], "rule": rule, "path": path, "line": line}
        ),
        "lane_id": lane["id"],
        "rule_id": rule,
        "path": path,
        "line": line,
        "source_sha256": sources[path],
        "severity": severity,
        "flows": flows or [],
        "suppressed": suppressed,
        "state": "observed",
        "remediation": _resolution(rule),
        "regression": "Add a reproducer that fails before the repair and passes afterward, plus an allowed-behavior control.",
        "owner": None,
        "confidence": "requires_specialty_review",
        "closure_requirement": "Fresh candidate-bound analyzer, challenge, and independent review evidence; a suppression is not resolution.",
    }


def _resolution(rule: str) -> str:
    rules = (
        (
            r"command|shell|exec|eval",
            "Replace externally influenced shell/dynamic execution with explicit argv or allowlisted dispatch; reject hostile arguments.",
        ),
        (
            r"sql",
            "Use bound SQL parameters; retain authorization and test injection inputs at the actual query boundary.",
        ),
        (
            r"path|travers|archive",
            "Enforce a canonical destination boundary and reject traversal, absolute paths, and linked archive destinations.",
        ),
        (
            r"ssrf|redirect",
            "Restrict outbound destinations, resolved addresses and redirects; test private and loopback denial.",
        ),
        (
            r"auth|tenant|permission",
            "Enforce role and tenant ownership at the operation boundary; test denied, cross-tenant and permitted requests.",
        ),
        (
            r"secret|token|credential",
            "Revoke exposed credentials, remove their source/log propagation, and verify the approved secret-store path.",
        ),
        (
            r"deserial|pickle|yaml",
            "Use a non-executable input format or safe loader with schema validation and hostile-payload tests.",
        ),
        (
            r"cve-|ghsa-|osv",
            "Identify the affected resolved dependency, review a fixed version and compatibility impact, then rebuild and rescan its artifact.",
        ),
    )
    for pattern, resolution in rules:
        if re.search(pattern, rule, re.IGNORECASE):
            return resolution
    return "Inspect the rule and source trace, establish a reproducer, and repair the violated invariant without weakening its guard."


def _execution_sarif(report: dict, lane: dict, sources: dict) -> list:
    if report.get("version") != "2.1.0":
        raise RuntimeAuditError("E_SARIF_VERSION", "SARIF 2.1.0 required")
    findings = []
    for run in _list(report.get("runs"), 1, 16):
        driver = _object(_object(run.get("tool")).get("driver"))
        analyzer = {"driver": driver.get("name"), "version": driver.get("version")}
        require_str(analyzer["driver"], "driver")
        require_str(analyzer["version"], "version")
        names = {
            "codeql": {"codeql"},
            "semgrep": {"semgrep", "semgrep oss"},
            "gitleaks": {"gitleaks"},
            "trivy": {"trivy"},
        }
        if (
            analyzer["driver"].lower() not in names[lane["engine"]]
            or analyzer["version"] != lane["tool_version"]
        ):
            raise RuntimeAuditError(
                "E_ANALYZER_MISMATCH",
                "native driver/version differs from the pinned adapter",
            )
        _completed(run, analyzer)
        for invocation in run["invocations"]:
            for key in ("toolExecutionNotifications", "toolConfigurationNotifications"):
                if any(
                    item.get("level", "warning") in {"warning", "error"}
                    for item in invocation.get(key, [])
                ):
                    raise RuntimeAuditError(
                        "E_ANALYZER_INCOMPLETE",
                        "unclassified analyzer warning or error prevents full coverage",
                    )
        results = _list(run.get("results"), 0, 20_000)
        _check_rule_indices(run, results)
        rules = {item["id"]: item for item in driver.get("rules", [])}
        for result in results:
            if result.get("kind", "fail") in {"pass", "notApplicable", "informational"}:
                continue
            location = _location(_list(result.get("locations"), 1, 10)[0], sources)
            severity = result.get("level", "warning")
            score = (
                rules.get(result["ruleId"], {})
                .get("properties", {})
                .get("security-severity")
            )
            if score is not None:
                try:
                    numeric = float(score)
                    if not 0 <= numeric <= 10:
                        raise ValueError
                    severity = (
                        "critical"
                        if numeric >= 9
                        else "high"
                        if numeric >= 7
                        else "medium"
                        if numeric >= 4
                        else "low"
                    )
                except (ValueError, TypeError) as exc:
                    raise RuntimeAuditError(
                        "E_SEVERITY", "invalid security severity"
                    ) from exc
            findings.append(
                _execution_finding(
                    lane,
                    result["ruleId"],
                    location["path"],
                    location["start_line"],
                    severity,
                    sources,
                    flows=_flows(result, sources),
                    suppressed=bool(result.get("suppressions")),
                )
            )
    return findings


def _execution_osv(report: dict, lane: dict, sources: dict) -> list:
    findings = []
    if report.get("errors") or report.get("error"):
        raise RuntimeAuditError(
            "E_DEPENDENCY_ERRORS", "OSV reported unresolved analysis errors"
        )
    for result in _list(report.get("results"), 1, 20_000):
        path = relative_path(_object(result.get("source")).get("path"))
        if path not in sources:
            raise RuntimeAuditError("E_TRACE_UNBOUND", "dependency manifest is unbound")
        for package in _list(result.get("packages"), 1, 20_000):
            identity = _object(package.get("package"))
            for key in ("name", "version", "ecosystem"):
                require_str(identity.get(key), f"package.{key}")
            for vulnerability in _list(package.get("vulnerabilities", []), 0, 20_000):
                findings.append(
                    _execution_finding(
                        lane, vulnerability.get("id"), path, 1, "high", sources
                    )
                )
    return findings


def _execution_runtime(report: dict, lane: dict, sources: dict) -> list:
    if (
        report.get("schema") != f"factory.deep-{lane['engine']}-observations.v1"
        or report.get("engine") != lane["engine"]
        or report.get("tool_version") != lane["tool_version"]
        or report.get("completed") is not True
        or report.get("errors") != []
    ):
        raise RuntimeAuditError(
            "E_RUNTIME_REPORT", "engine-specific completed runtime evidence required"
        )
    harness = _object(report.get("harness"))
    if (
        harness.get("path") not in sources
        or harness.get("sha256") != sources[harness["path"]]
    ):
        raise RuntimeAuditError(
            "E_HARNESS_BINDING", "harness must bind candidate source"
        )
    metrics = _object(report.get("metrics"))
    keys = (
        ("executions", "coverage_edges", "corpus_size")
        if lane["family"] == "fuzz"
        else ("requests",)
        if lane["engine"] == "zap"
        else ("tests",)
    )
    for key in keys:
        require_int(metrics.get(key), key, minimum=1, maximum=10**12)
    return [
        _execution_finding(
            lane,
            item.get("rule_id"),
            item.get("path"),
            item.get("line"),
            item.get("severity"),
            sources,
        )
        for item in _list(report.get("findings"), 0, 20_000)
    ]


def _native_accounting(report: dict, lane: dict, required: dict) -> None:
    if lane["engine"] == "osv":
        paths = [item["source"]["path"] for item in report["results"]]
        if len(set(paths)) != len(paths) or set(paths) != set(required):
            raise RuntimeAuditError(
                "E_DEPENDENCY_COVERAGE",
                "native OSV results must account for every input exactly once",
            )
    elif lane["engine"] == "syft":
        paths = {
            item["path"].removeprefix("/src/")
            for artifact in report["artifacts"]
            for item in artifact["locations"]
        }
        if paths != set(required):
            raise RuntimeAuditError(
                "E_DEPENDENCY_COVERAGE",
                "native SBOM locations must account for every dependency input",
            )
    elif lane["family"] in {"runtime", "fuzz"}:
        coverage = _object(report.get("source_coverage"))
        if set(coverage) != set(required):
            raise RuntimeAuditError(
                "E_RUNTIME_COVERAGE",
                "runtime coverage must account for every declared source",
            )
        for path, source_hash in required.items():
            item = _object(coverage[path])
            if item.get("sha256") != source_hash:
                raise RuntimeAuditError(
                    "E_RUNTIME_COVERAGE", "runtime source bytes differ"
                )
            for kind in ("lines", "branches"):
                total = require_int(
                    item.get(f"{kind}_total"),
                    kind,
                    minimum=1 if kind == "lines" else 0,
                    maximum=10**9,
                )
                if (
                    type(item.get(f"{kind}_covered")) is not int
                    or item[f"{kind}_covered"] != total
                ):
                    raise RuntimeAuditError(
                        "E_RUNTIME_COVERAGE",
                        "uncovered runtime lines or branches remain",
                    )


def _challenge_semantics(
    report: dict, lane: dict, bound: dict, obligation: dict, kind: str, sources: dict
) -> None:
    if (
        report.get("schema") != "factory.deep-challenge-observation.v1"
        or report.get("engine") != lane["engine"]
        or report.get("fixture_sha256") != bound["fixture_sha256"]
        or report.get("detector_rule_id") != obligation["detector_rule_id"]
        or report.get("detector_enabled") is not (kind != "mutation")
    ):
        raise RuntimeAuditError(
            "E_CHALLENGE_SEMANTICS", "challenge identity or detector state differs"
        )
    native = _object(report.get("native_report"))
    findings = _native_execution_report(native, lane, sources)
    rules = {item["rule_id"] for item in findings if not item["suppressed"]}
    if lane["engine"] == "syft":
        rules = {item["id"] for item in native["artifacts"]}
    detected = obligation["detector_rule_id"] in rules
    if detected != (kind == "positive"):
        raise RuntimeAuditError(
            "E_CHALLENGE_SEMANTICS",
            "positive must detect; negative and disabled-detector mutation must not",
        )


def _native_execution_report(report: dict, lane: dict, sources: dict) -> list:
    engine = lane["engine"]
    if engine in {"codeql", "semgrep", "gitleaks", "trivy"}:
        return _execution_sarif(report, lane, sources)
    if engine == "osv":
        return _execution_osv(report, lane, sources)
    if engine == "syft":
        artifacts = _list(report.get("artifacts"), 1, 50_000)
        require_str(_object(report.get("descriptor")).get("version"), "syft.version")
        if (
            _object(report.get("descriptor")).get("name") != "syft"
            or report["descriptor"]["version"] != lane["tool_version"]
            or report.get("errors")
            or report.get("error")
        ):
            raise RuntimeAuditError("E_SBOM", "native Syft JSON required")
        require_str(_object(report.get("schema")).get("version"), "schema.version")
        source = _object(report.get("source"))
        if source.get("type") != "directory" or source.get("target") != "/src":
            raise RuntimeAuditError(
                "E_SBOM_SOURCE", "SBOM must describe the mounted source snapshot"
            )
        for artifact in artifacts:
            for key in ("id", "name", "version", "type"):
                require_str(artifact.get(key), f"artifact.{key}")
            locations = _list(artifact.get("locations"), 1, 128)
            for location in locations:
                name = require_str(location.get("path"), "artifact.path").removeprefix(
                    "/src/"
                )
                if relative_path(name) not in sources:
                    raise RuntimeAuditError(
                        "E_SBOM_SOURCE", "component location is unbound"
                    )
        return []  # SBOM enumeration never substitutes for an OSV vulnerability lane.
    # ZAP/fuzz/harness adapters must map observations to candidate source paths.
    # Raw URL-only ZAP output is not source-depth coverage.
    return _execution_runtime(report, lane, sources)


def normalize_execution_bundle(
    bundle: dict, lane: dict, inventory: dict, run_id: str, obligations: list
) -> dict:
    """Check bounded worker evidence. Coverage remains an independently reviewed claim."""
    if (
        set(bundle) != {"schema", "run_id", "candidate_sha256", "artifacts"}
        or bundle["schema"] != "factory.deep-worker.v1"
    ):
        raise RuntimeAuditError("E_WORKER_SCHEMA", "unexpected worker envelope")
    if (
        bundle["run_id"] != run_id
        or bundle["candidate_sha256"] != inventory["candidate_sha256"]
    ):
        raise RuntimeAuditError(
            "E_WORKER_BINDING", "worker output belongs to another run or candidate"
        )
    artifacts = _object(bundle["artifacts"])
    if set(artifacts) != {
        lane[key] for key in ("report", "coverage", "challenge_report")
    }:
        raise RuntimeAuditError("E_WORKER_ARTIFACTS", "missing or unexpected artifact")
    report = _object(artifacts[lane["report"]])
    coverage = _object(artifacts[lane["coverage"]])
    challenges = _object(artifacts[lane["challenge_report"]])
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    findings = _native_execution_report(report, lane, sources)
    gaps = []
    required = {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }
    _native_accounting(report, lane, required)
    if (
        not required
        or coverage.get("schema") != "factory.deep-coverage.v1"
        or coverage.get("sources") != required
    ):
        gaps.append("SOURCE_COVERAGE_MISSING")
    if coverage.get("complete") is not True or coverage.get("errors") != []:
        gaps.append("ANALYZER_INCOMPLETE")
    if coverage.get("mode") != lane["mode"] or coverage.get("fallback") is not False:
        gaps.append("ANALYSIS_MODE_DOWNGRADE")
    if coverage.get("report_sha256") != digest(report):
        gaps.append("COVERAGE_REPORT_DRIFT")
    for key in ("tool_version", "ruleset_sha256", "invocation_sha256"):
        if key == "tool_version":
            require_str(coverage.get(key), key)
        else:
            require_digest(coverage.get(key), key)
    if (
        coverage["tool_version"] != lane["tool_version"]
        or coverage["ruleset_sha256"] != lane["ruleset_sha256"]
    ):
        gaps.append("TOOLCHAIN_DRIFT")
    expected = {
        item["id"]
        for item in obligations
        if item["family"] == lane["family"]
        and item["engine"] == lane["engine"]
        and set(item["paths"]) <= set(required)
    }
    observed = _list(coverage.get("obligations"), 0, 4096)
    if (
        any(not isinstance(item, str) for item in observed)
        or set(observed) != expected
        or not expected
    ):
        gaps.append("OBLIGATION_COVERAGE_MISSING")
    if challenges.get("schema") != "factory.deep-challenges.v1":
        raise RuntimeAuditError("E_CHALLENGE_SCHEMA", "expected challenge observations")
    seen = set()
    approved = {
        (item["id"], challenge["kind"]): challenge
        for item in obligations
        if item["id"] in expected
        for challenge in item["challenges"]
    }
    for challenge in _list(challenges.get("observations"), 0, 8192):
        identity = (
            require_str(challenge.get("obligation_id"), "obligation"),
            _enum(challenge.get("kind"), {"positive", "negative", "mutation"}),
        )
        if identity in seen:
            raise RuntimeAuditError("E_CHALLENGE_DUPLICATE", "duplicate challenge")
        seen.add(identity)
        for key in ("fixture_sha256", "observation_sha256"):
            require_digest(challenge.get(key), key)
        bound = approved.get(identity)
        report_evidence = _object(challenge.get("report"))
        report_digest = digest(report_evidence)
        if bound is not None:
            obligation = next(item for item in obligations if item["id"] == identity[0])
            _challenge_semantics(
                report_evidence, lane, bound, obligation, identity[1], sources
            )
        if (
            bound is None
            or challenge["fixture_sha256"] != bound["fixture_sha256"]
            or sources.get(bound["fixture_path"]) != bound["fixture_sha256"]
            or report_digest != challenge["observation_sha256"]
            or report_digest != bound["expected_report_sha256"]
            or type(challenge.get("exit_code")) is not int
            or challenge["exit_code"] != bound["expected_exit_code"]
        ):
            gaps.append("CHALLENGE_FAILED")
    if seen != {
        (identity, kind)
        for identity in expected
        for kind in ("positive", "negative", "mutation")
    }:
        gaps.append("CHALLENGE_COVERAGE_MISSING")
    return {
        "lane_id": lane["id"],
        "engine": lane["engine"],
        "family": lane["family"],
        "state": "INCOMPLETE" if gaps else "OBSERVED",
        "gaps": sorted(set(gaps)),
        "report_sha256": digest(report),
        "coverage_sha256": digest(coverage),
        "challenge_sha256": digest(challenges),
        "covered_paths": sorted(required),
        "obligations": observed,
        "findings": findings,
        "authority": "none",
    }


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
        raise RuntimeAuditError(
            "E_SARIF_INDIRECTION", "expand artifact references before ingestion"
        )
    path = relative_path(artifact.get("uri"))
    if path not in sources:
        raise RuntimeAuditError("E_TRACE_UNBOUND", "location has no source binding")
    region = _object(physical.get("region"))
    line = require_int(
        region.get("startLine"), "startLine", minimum=1, maximum=10_000_000
    )
    end = require_int(
        region.get("endLine", line), "endLine", minimum=line, maximum=10_000_000
    )
    column = require_int(
        region.get("startColumn", 1), "startColumn", minimum=1, maximum=10_000_000
    )
    end_column = require_int(
        region.get("endColumn", column), "endColumn", minimum=1, maximum=10_000_000
    )
    if end == line and end_column < column:
        raise RuntimeAuditError("E_SARIF_SHAPE", "reversed columns")
    return {
        "path": path,
        "source_sha256": sources[path],
        "start_line": line,
        "end_line": end,
        "start_column": column,
        "end_column": end_column,
    }


def _flows(result: dict, sources: dict) -> list:
    flows = []
    total = 0
    for flow in _list(result.get("codeFlows", []), 0, 16):
        for thread in _list(_object(flow).get("threadFlows"), 1, 16):
            steps = []
            for step in _list(_object(thread).get("locations"), 1, 128):
                step = _object(step)
                if "index" in step:
                    raise RuntimeAuditError(
                        "E_SARIF_INDIRECTION",
                        "expand thread locations before ingestion",
                    )
                kinds = _list(step.get("kinds", []), 0, 16)
                kinds = sorted(
                    {require_str(kind, "kind", maximum=128) for kind in kinds}
                )
                steps.append(
                    {**_location(step.get("location"), sources), "kinds": kinds}
                )
                total += 1
                if total > 128:
                    raise RuntimeAuditError(
                        "E_TRACE_LIMIT", "finding exceeds 128 flow steps"
                    )
            flows.append(steps)
    return flows


def _native(result: dict) -> dict:
    native = {}
    for group in ("partialFingerprints", "fingerprints"):
        for key, value in _object(result.get(group, {})).items():
            name = require_str(key, "fingerprint key", maximum=128)
            native[group + ":" + name] = require_str(value, "fingerprint", maximum=1024)
    if not 1 <= len(native) <= 16:
        raise RuntimeAuditError(
            "E_NATIVE_FINGERPRINT", "require 1..16 native fingerprints"
        )
    return native


def _suppression(result: dict) -> list:
    output = []
    for value in _list(result.get("suppressions", []), 0, 16):
        item = _object(value)
        output.append(
            {
                "kind": _enum(item.get("kind"), {"inSource", "external"}),
                "status": _enum(
                    item.get("status", "underReview"),
                    {"accepted", "underReview", "rejected"},
                ),
            }
        )
    return sorted(output, key=lambda item: (item["kind"], item["status"]))


def _finding(result: object, analyzer: dict, sources: dict) -> dict:
    result = _object(result)
    if "rule" in result:
        raise RuntimeAuditError(
            "E_SARIF_INDIRECTION", "expand rule references before ingestion"
        )
    rule = require_str(result.get("ruleId"), "ruleId")
    native = _native(result)
    flows = _flows(result, sources)
    locations = [
        _location(item, sources) for item in _list(result.get("locations"), 1, 10)
    ]
    suppressions = _suppression(result)
    return {
        "finding_id": digest(
            {
                "schema": "factory.deep-finding-identity.v1",
                "analyzer": analyzer["id"],
                "rule": rule,
                "native": native,
            }
        ),
        "native_fingerprint_sha256": digest(native),
        "rule_id": rule,
        "analyzer_id": analyzer["id"],
        "kind": _enum(
            result.get("kind", "fail"),
            {"notApplicable", "pass", "fail", "review", "open", "informational"},
        ),
        "level": _enum(
            result.get("level", "warning"), {"none", "note", "warning", "error"}
        ),
        "baseline": _enum(
            result.get("baselineState", "unbaselined"),
            {"new", "updated", "unchanged", "absent", "unbaselined"},
        ),
        "locations": locations,
        "flows": flows,
        "trace_sha256": digest({"locations": locations, "flows": flows}),
        "trace_depth": max((len(flow) for flow in flows), default=0),
        "suppressions": suppressions,
        "suppressed": any(item["status"] != "rejected" for item in suppressions),
    }


def _completed(run: dict, analyzer: dict) -> None:
    tool = _object(run.get("tool"))
    driver = _object(tool.get("driver"))
    if tool.get("extensions") or run.get("externalPropertyFileReferences"):
        raise RuntimeAuditError(
            "E_SARIF_INDIRECTION", "external tool/property references unsupported"
        )
    if (
        driver.get("name") != analyzer["driver"]
        or driver.get("version") != analyzer["version"]
    ):
        raise RuntimeAuditError(
            "E_ANALYZER_MISMATCH", "driver/version does not match declaration"
        )
    for invocation in _list(run.get("invocations"), 1, 16):
        invocation = _object(invocation)
        if invocation.get("executionSuccessful") is not True:
            raise RuntimeAuditError(
                "E_ANALYZER_INCOMPLETE", "analyzer completion missing or false"
            )
        for key in ("toolExecutionNotifications", "toolConfigurationNotifications"):
            for notification in _list(invocation.get(key, []), 0, 128):
                if (
                    _enum(
                        _object(notification).get("level", "warning"),
                        {"none", "note", "warning", "error"},
                    )
                    == "error"
                ):
                    raise RuntimeAuditError(
                        "E_ANALYZER_INCOMPLETE", "analyzer reported error notification"
                    )


def _check_rule_indices(run: dict, results: list) -> None:
    rules = _list(run["tool"]["driver"].get("rules", []), 0, 20_000)
    ids = [require_str(_object(rule).get("id"), "rule id") for rule in rules]
    if len(set(ids)) != len(ids):
        raise RuntimeAuditError("E_DUPLICATE_RULE", "duplicate driver rule ids")
    defaults = {
        rule["id"]: _object(rule.get("defaultConfiguration", {})).get(
            "level", "warning"
        )
        for rule in rules
    }
    for result in results:
        result = _object(result)
        if "ruleIndex" in result:
            index = require_int(
                result["ruleIndex"],
                "ruleIndex",
                minimum=0,
                maximum=max(0, len(ids) - 1),
            )
            if not ids or ids[index] != result.get("ruleId"):
                raise RuntimeAuditError("E_SARIF_INDIRECTION", "rule index/id mismatch")
        if "level" not in result:
            result["level"] = defaults.get(result.get("ruleId"), "warning")


def normalize_sarif(
    root: Path, binding: dict, analyzer: dict, source_hashes: dict
) -> dict:
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
        raise RuntimeAuditError(
            "E_DUPLICATE_FINDING", "native finding identity collision"
        )
    for path, value in source_hashes.items():
        bound_bytes(root, {"path": path, "sha256": value})
    bound_bytes(root, binding)
    result = {
        "schema": "factory.deep-sarif.v1",
        "analyzer": {key: analyzer[key] for key in ("id", "driver", "version")},
        "report_sha256": binding["sha256"],
        "findings": sorted(findings, key=lambda item: item["finding_id"]),
        "authority": "none",
    }
    return {**result, "normalized_sha256": digest(result)}
