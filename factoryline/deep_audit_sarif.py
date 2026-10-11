"""Strict SARIF subset with native identities and source-bound ordered flow evidence.

This parser does not verify signer authority, execute scanners, or decide release.
Unrecognized SARIF indirection is rejected rather than silently dropping evidence.
"""

from __future__ import annotations

from pathlib import Path
from copy import deepcopy
import re

from .deep_audit_io import bound_bytes, digest, relative_path, sha256_bytes, strict_json
from .runtime_audit_common import (
    RuntimeAuditError,
    canonical_bytes,
    require_digest,
    require_int,
    require_str,
)

_NATIVE_REPORT_ROLES = {
    "codeql": "sarif_report",
    "semgrep": "sarif_report",
    "trivy": "sarif_report",
    "osv": "osv_json_report",
    "gitleaks": "sarif_report",
    "runtime": "junit_xml",
    "atheris": "fuzz_result",
    "jazzer": "fuzz_result",
    "zap": "zap_report",
}


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


def _sarif_analyzer(run, lane):
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
    return driver, analyzer


def _check_invocations(run):
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


def _severity(score, default):
    if score is None:
        return default
    try:
        numeric = float(score)
    except (ValueError, TypeError) as exc:
        raise RuntimeAuditError("E_SEVERITY", "invalid security severity") from exc
    if not 0 <= numeric <= 10:
        raise RuntimeAuditError("E_SEVERITY", "invalid security severity")
    if numeric >= 9:
        return "critical"
    if numeric >= 7:
        return "high"
    if numeric >= 4:
        return "medium"
    return "low"


def _sarif_result_finding(result, rules, lane, sources):
    if result.get("kind", "fail") in {"pass", "notApplicable", "informational"}:
        return None
    location = _location(_list(result.get("locations"), 1, 10)[0], sources)
    score = (
        rules.get(result["ruleId"], {}).get("properties", {}).get("security-severity")
    )
    flows = _flows(result, sources)
    finding = _execution_finding(
        lane,
        result["ruleId"],
        location["path"],
        location["start_line"],
        _severity(score, result.get("level", "warning")),
        sources,
        flows=flows,
        suppressed=bool(result.get("suppressions")),
    )

    locations = [
        _location(item, sources) for item in _list(result.get("locations"), 1, 10)
    ]
    finding["trace_sha256"] = digest({"locations": locations, "flows": flows})
    finding["trace_depth"] = max((len(flow) for flow in flows), default=0)
    native = (
        _native(result)
        if result.get("partialFingerprints") or result.get("fingerprints")
        else None
    )
    finding["native_fingerprint_sha256"] = digest(native) if native else None
    finding["native_identity_state"] = "MEASURED" if native else "NOT_MEASURED"
    return finding


def _sarif_run_findings(run, lane, sources):
    driver, analyzer = _sarif_analyzer(run, lane)
    _completed(run, analyzer)
    _check_invocations(run)
    results = _list(run.get("results"), 0, 20_000)
    _check_rule_indices(run, results)
    rules = {item["id"]: item for item in driver.get("rules", [])}
    return [
        finding
        for result in results
        if (finding := _sarif_result_finding(result, rules, lane, sources)) is not None
    ]


def _execution_sarif(report: dict, lane: dict, sources: dict) -> list:
    # Rule defaults are normalized on a copy; native hashes bind original bytes.
    report = deepcopy(report)
    if report.get("version") != "2.1.0":
        raise RuntimeAuditError("E_SARIF_VERSION", "SARIF 2.1.0 required")
    findings = []
    for run in _list(report.get("runs"), 1, 16):
        findings.extend(_sarif_run_findings(run, lane, sources))
    return findings


def _execution_osv(report: dict, lane: dict, sources: dict) -> list:
    findings = []
    if report.get("errors") or report.get("error"):
        raise RuntimeAuditError(
            "E_DEPENDENCY_ERRORS", "OSV reported unresolved analysis errors"
        )
    for result in _list(report.get("results"), 0, 20_000):
        path = relative_path(_object(result.get("source")).get("path"))
        if path not in sources:
            raise RuntimeAuditError("E_TRACE_UNBOUND", "dependency manifest is unbound")
        for package in _list(result.get("packages"), 1, 20_000):
            identity = _object(package.get("package"))
            for key in ("name", "version", "ecosystem"):
                require_str(identity.get(key), f"package.{key}", maximum=256)
            for vulnerability in _list(package.get("vulnerabilities", []), 0, 20_000):
                vulnerability = _object(vulnerability)
                advisory_id = _safe_text(
                    require_str(
                        vulnerability.get("id"), "vulnerability.id", maximum=256
                    ),
                    256,
                )
                package_facts = {
                    key: _safe_text(identity[key], 256)
                    for key in ("name", "version", "ecosystem")
                }
                fixed_versions = _osv_fixed_versions(vulnerability, identity)
                finding = _execution_finding(
                    lane, advisory_id, path, 1, "high", sources
                )
                finding["dependency"] = {
                    "package": package_facts,
                    "advisory_id": advisory_id,
                    "fixed_versions": fixed_versions,
                    "aliases": [
                        _safe_text(
                            require_str(alias, "advisory alias", maximum=256), 256
                        )
                        for alias in _list(vulnerability.get("aliases", []), 0, 256)
                    ],
                }
                if fixed_versions:
                    finding["remediation"] = (
                        f"Upgrade {package_facts['ecosystem']} package "
                        f"{package_facts['name']} from {package_facts['version']} "
                        f"to a fixed version: {', '.join(fixed_versions)}."
                    )
                findings.append(finding)
    return findings


def _osv_fixed_versions(vulnerability: dict, identity: dict) -> list[str]:
    fixed = set()
    for affected in _list(vulnerability.get("affected", []), 0, 20_000):
        affected = _object(affected)
        package = _object(affected.get("package", {}))
        matches = (
            package.get("name") == identity["name"]
            and package.get("ecosystem") == identity["ecosystem"]
        )
        for range_item in _list(affected.get("ranges", []), 0, 20_000):
            range_item = _object(range_item)
            for event in _list(range_item.get("events", []), 0, 20_000):
                event = _object(event)
                if "fixed" in event:
                    version = require_str(event["fixed"], "fixed version", maximum=256)
                    if matches:
                        fixed.add(_safe_text(version, 256))
    return sorted(fixed)


def _validate_runtime_report(report, lane):
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
    return _object(report.get("harness")), _object(report.get("metrics"))


def _validate_runtime_harness(harness, sources):
    if (
        harness.get("path") not in sources
        or harness.get("sha256") != sources[harness["path"]]
    ):
        raise RuntimeAuditError(
            "E_HARNESS_BINDING", "harness must bind candidate source"
        )


def _validate_runtime_metrics(metrics, lane):
    keys = (
        ("executions", "coverage_edges", "corpus_size")
        if lane["family"] == "fuzz"
        else ("requests",)
        if lane["engine"] == "zap"
        else ("tests",)
    )
    for key in keys:
        require_int(metrics.get(key), key, minimum=1, maximum=10**12)


def _execution_runtime(report: dict, lane: dict, sources: dict) -> list:
    harness, metrics = _validate_runtime_report(report, lane)
    _validate_runtime_harness(harness, sources)
    _validate_runtime_metrics(metrics, lane)
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


def _native_osv_accounting(report, required):
    paths = [item["source"]["path"] for item in report["results"]]
    if len(set(paths)) != len(paths) or set(paths) != set(required):
        raise RuntimeAuditError(
            "E_DEPENDENCY_COVERAGE",
            "native OSV results must account for every input exactly once",
        )


def _native_syft_accounting(report, required):
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


def _native_runtime_accounting(report, required):
    coverage = _object(report.get("source_coverage"))
    if set(coverage) != set(required):
        raise RuntimeAuditError(
            "E_RUNTIME_COVERAGE",
            "runtime coverage must account for every declared source",
        )
    for path, source_hash in required.items():
        _runtime_source_accounting(_object(coverage[path]), source_hash)


def _runtime_source_accounting(item, source_hash):
    if item.get("sha256") != source_hash:
        raise RuntimeAuditError("E_RUNTIME_COVERAGE", "runtime source bytes differ")
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
                "E_RUNTIME_COVERAGE", "uncovered runtime lines or branches remain"
            )


def _native_accounting(report: dict, lane: dict, required: dict) -> None:
    if lane["engine"] == "osv":
        return _native_osv_accounting(report, required)
    if lane["engine"] == "syft":
        return _native_syft_accounting(report, required)
    if lane["family"] in {"runtime", "fuzz"}:
        return _native_runtime_accounting(report, required)


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
    _challenge_findings_valid(findings, native, lane, obligation, kind)


def _challenge_findings_valid(findings, native, lane, obligation, kind):
    rules = {item["rule_id"] for item in findings if not item["suppressed"]}
    if lane["engine"] == "syft":
        rules = {item["id"] for item in native["artifacts"]}
    detected = obligation["detector_rule_id"] in rules
    clean_negative_failed = (
        lane["engine"] in {"gitleaks", "semgrep"} and kind == "negative" and bool(rules)
    )
    if detected != (kind == "positive") or clean_negative_failed:
        raise RuntimeAuditError(
            "E_CHALLENGE_SEMANTICS",
            "challenge finding set differs from its signed oracle",
        )


def _execution_syft(report, lane, sources):
    artifacts = _list(report.get("artifacts"), 1, 50_000)
    descriptor = _object(report.get("descriptor"))
    require_str(descriptor.get("version"), "syft.version")
    if (
        descriptor.get("name") != "syft"
        or descriptor["version"] != lane["tool_version"]
        or report.get("errors")
        or report.get("error")
    ):
        raise RuntimeAuditError("E_SBOM", "native Syft JSON required")
    require_str(_object(report.get("schema")).get("version"), "schema.version")
    source = _object(report.get("source"))
    target = source.get("target")
    if target is None:
        target = _object(source.get("metadata")).get("path")
    if source.get("type") != "directory" or target != "/src":
        raise RuntimeAuditError(
            "E_SBOM_SOURCE", "SBOM must describe the mounted source snapshot"
        )
    for artifact in artifacts:
        _validate_syft_artifact(artifact, sources)
    return []  # SBOM enumeration never substitutes for an OSV vulnerability lane.


def _validate_syft_artifact(artifact, sources):
    for key in ("id", "name", "version", "type"):
        require_str(artifact.get(key), f"artifact.{key}")
    for location in _list(artifact.get("locations"), 1, 128):
        name = require_str(location.get("path"), "artifact.path").removeprefix("/src/")
        if relative_path(name) not in sources:
            raise RuntimeAuditError("E_SBOM_SOURCE", "component location is unbound")


def _native_execution_report(report: dict, lane: dict, sources: dict) -> list:
    engine = lane["engine"]
    if engine in {"codeql", "semgrep", "gitleaks", "trivy"}:
        return _execution_sarif(report, lane, sources)
    if engine == "osv":
        return _execution_osv(report, lane, sources)
    if engine == "syft":
        return _execution_syft(report, lane, sources)
    # ZAP/fuzz/harness adapters must map observations to candidate source paths.
    # Raw URL-only ZAP output is not source-depth coverage.
    return _execution_runtime(report, lane, sources)


def _worker_artifacts(bundle, lane, inventory, run_id):
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
    _bind_native_inventory(coverage, lane, inventory)
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    return report, coverage, challenges, sources


def _bind_native_inventory(coverage, lane, inventory):
    if lane["engine"] != "gitleaks" or "native_source_inventory" not in coverage:
        return
    if (
        coverage.get("native_source_inventory") != inventory.get("files")
        or coverage.get("candidate_sha256") != inventory.get("candidate_sha256")
        or coverage.get("native_source_inventory_sha256")
        != inventory.get("candidate_sha256")
    ):
        raise RuntimeAuditError(
            "E_WORKER_BINDING", "native source inventory differs from candidate"
        )


def _required_sources(inventory, lane):
    return {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }


def _coverage_source_gaps(report, coverage, lane, required):
    gaps = []
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
    return gaps


def _rule_accounting_shape(accounting, lane, required):
    if not isinstance(accounting, dict) or set(accounting) != {
        "schema",
        "ruleset_sha256",
        "rule_inventory_sha256",
        "native_ledger_sha256",
        "native_source_inventory_sha256",
        "accounting_sha256",
        "invocation_sha256",
        "native_report_sha256",
        "rules",
    }:
        return ["RULE_ACCOUNTING_MISSING"]
    rule_ids = lane.get("rule_ids")
    if not isinstance(rule_ids, list) or not rule_ids:
        return ["RULE_INVENTORY_MISSING"]
    if not isinstance(accounting.get("rules"), list) or len(accounting["rules"]) > 4096:
        return ["RULE_ACCOUNTING_MISSING"]
    if len(accounting["rules"]) != len(rule_ids):
        return ["RULE_ACCOUNTING_INVENTORY_DRIFT"]
    if len(rule_ids) * len(required) > 200_000:
        return ["RULE_ACCOUNTING_BUDGET_EXCEEDED"]
    return []


def _rule_inventory_gaps(coverage, lane):
    inventory = coverage.get("rule_inventory")
    if not isinstance(inventory, dict) or set(inventory) != {
        "state",
        "rule_ids",
        "sha256",
    }:
        return ["RULE_INVENTORY_UNVERIFIED"]
    rule_ids = lane.get("rule_ids")
    if (
        inventory["state"] != "VERIFIED"
        or not isinstance(rule_ids, list)
        or not rule_ids
        or inventory["rule_ids"] != sorted(rule_ids)
    ):
        return ["RULE_INVENTORY_UNVERIFIED"]
    expected = digest(
        {"ruleset_sha256": lane["ruleset_sha256"], "rule_ids": sorted(rule_ids)}
    )
    return [] if inventory["sha256"] == expected else ["RULE_INVENTORY_DRIFT"]


def _rule_source_rows(rule, required):
    if not isinstance(rule, dict) or set(rule) != {"rule_id", "sources"}:
        return None
    rows = rule.get("sources")
    if not isinstance(rows, list) or len(rows) != len(required):
        return None
    observed = {}
    for row in rows:
        parsed = _rule_source_row(row, required, observed)
        if parsed is None:
            return None
        observed[parsed[0]] = parsed[1]
    return observed if set(observed) == set(required) else None


def _rule_source_row(row, required, observed):
    if not isinstance(row, dict) or set(row) != {
        "path",
        "source_sha256",
        "disposition",
        "native_counts",
        "evidence_sha256",
    }:
        return None
    path = row["path"]
    if not isinstance(path, str) or path not in required or path in observed:
        return None
    if (
        row["source_sha256"] != required[path]
        or not _rule_disposition_valid(row)
        or not _native_counts_valid(row["native_counts"])
    ):
        return None
    try:
        require_digest(row["evidence_sha256"], "rule evidence")
    except RuntimeAuditError:
        return None
    return path, row["disposition"]


def _rule_disposition_valid(row):
    return isinstance(row["disposition"], str) and row["disposition"] in {
        "configured",
        "ingested",
        "executed",
        "suppressed",
        "not_applicable",
        "failed",
        "not_run",
    }


def _native_counts_valid(counts):
    allowed = {
        "attempted",
        "suppressed_skip_report",
        "suppressed_rule_allowlist",
        "suppressed_global_allowlist",
        "path_evaluated",
        "not_applicable_path_mismatch",
        "not_applicable_no_regex",
        "not_run_size_limit",
        "regex_executed",
        "regex_match",
        "finding",
    }
    return (
        isinstance(counts, dict)
        and set(counts) <= allowed
        and (
            "attempted" not in counts
            or (type(counts["attempted"]) is int and counts["attempted"] > 0)
        )
        and all(
            type(value) is int and 0 < value <= 2**63 - 1 for value in counts.values()
        )
        and counts.get("attempted", 0)
        >= max(counts.get("regex_executed", 0), counts.get("path_evaluated", 0))
        and counts.get("finding", 0) <= counts.get("regex_match", 0)
    )


def _native_rule_ledger_gaps(coverage, lane, required, report):
    native_sources = _native_source_inventory(coverage, required)
    if native_sources is None:
        return ["RULE_NATIVE_SOURCE_INVENTORY_INVALID"]
    ledger, error = _parse_native_ledger(coverage)
    if error:
        return [error]
    if not _native_ledger_valid(ledger, coverage, lane):
        return ["RULE_NATIVE_LEDGER_INCOMPLETE"]
    return _native_ledger_matrix(
        ledger, coverage, lane, required, native_sources, report
    )


def _parse_native_ledger(coverage):
    text = coverage.get("native_rule_ledger_json")
    ledger_sha = coverage.get("native_rule_ledger_sha256")
    if not isinstance(text, str) or not isinstance(ledger_sha, str):
        return None, "RULE_NATIVE_LEDGER_MISSING"
    try:
        raw = text.encode("utf-8")
        if len(raw) > 8 * 1024 * 1024:
            return None, "RULE_NATIVE_LEDGER_INVALID"
        require_digest(ledger_sha, "native ledger")
        if sha256_bytes(raw) != ledger_sha:
            return None, "RULE_NATIVE_LEDGER_DRIFT"
        return strict_json(raw), None
    except (RuntimeAuditError, UnicodeError):
        return None, "RULE_NATIVE_LEDGER_INVALID"


def _native_ledger_valid(ledger, coverage, lane):
    keys = {
        "schema",
        "root_sha256",
        "source_identity_kind",
        "source_sha256",
        "config_sha256",
        "prefilter_bypassed",
        "complete",
        "overflow",
        "invalid_paths",
        "rows",
    }
    return (
        isinstance(ledger, dict)
        and set(ledger) == keys
        and _native_ledger_identity(ledger, coverage, lane)
        and _native_ledger_status(ledger)
        and isinstance(ledger["rows"], list)
        and len(ledger["rows"]) <= 200_000
    )


def _native_ledger_identity(ledger, coverage, lane):
    return (
        ledger["schema"] == "gitleaks.factory-rule-ledger.v1"
        and ledger["source_identity_kind"] == "adapter_candidate_sha256"
        and ledger["source_sha256"] == coverage.get("candidate_sha256")
        and ledger["config_sha256"] == lane["ruleset_sha256"]
        and ledger["root_sha256"] == sha256_bytes(b"/src")
    )


def _native_ledger_status(ledger):
    return (
        ledger["prefilter_bypassed"] is True
        and ledger["complete"] is True
        and ledger["overflow"] is False
        and type(ledger["invalid_paths"]) is int
        and ledger["invalid_paths"] == 0
    )


def _native_source_inventory(coverage, required):
    files = coverage.get("native_source_inventory")
    candidate_sha = coverage.get("candidate_sha256")
    source_map_sha = coverage.get("native_source_inventory_sha256")
    if not isinstance(files, list) or len(files) > 50_000:
        return None
    try:
        require_digest(candidate_sha, "candidate")
        require_digest(source_map_sha, "native source inventory")
        if candidate_sha != source_map_sha or digest(files) != candidate_sha:
            return None
        sources = {}
        for item in files:
            parsed = _native_source_file(item)
            if parsed is None or parsed[0] in sources:
                return None
            path, source_sha = parsed
            sources[path] = source_sha
    except (RuntimeAuditError, TypeError):
        return None
    if any(sources.get(path) != source_sha for path, source_sha in required.items()):
        return None
    return sources


def _native_source_file(item):
    fields = {"path", "sha256", "bytes", "mode", "language"}
    if not isinstance(item, dict) or set(item) != fields:
        return None
    path = relative_path(item["path"])
    require_digest(item["sha256"], "native source")
    require_int(item["bytes"], "native source bytes", minimum=0, maximum=1_073_741_824)
    require_int(item["mode"], "native source mode", minimum=0, maximum=0o777)
    require_str(item["language"], "native source language", maximum=32)
    return path, item["sha256"]


def _native_ledger_matrix(ledger, coverage, lane, required, native_sources, report):
    observed, error = _native_ledger_rows(ledger, lane, native_sources)
    if error:
        return [error]
    if not _native_finding_counts_match(report, lane, native_sources, observed):
        return ["RULE_NATIVE_FINDING_COUNT_DRIFT"]
    return _native_accounting_gaps(coverage, observed)


def _native_finding_counts_match(report, lane, sources, observed):
    actual = {}
    for finding in _execution_sarif(report, lane, sources):
        key = (finding["path"], finding["rule_id"])
        actual[key] = actual.get(key, 0) + 1
    return all(
        observed.get(key, {}).get("finding", 0) == actual.get(key, 0)
        for key in set(observed) | set(actual)
    )


def _native_ledger_rows(ledger, lane, native_sources):
    observed = {}
    for row in ledger["rows"]:
        key, counts, error = _native_ledger_row(row, lane, native_sources, observed)
        if error:
            return None, error
        observed[key] = counts
    return observed, None


def _native_ledger_row(row, lane, native_sources, observed):
    if not isinstance(row, dict) or set(row) != {"path", "rule_id", "counts"}:
        return None, None, "RULE_NATIVE_LEDGER_INVALID"
    if not isinstance(row["path"], str) or not isinstance(row["rule_id"], str):
        return None, None, "RULE_NATIVE_LEDGER_INVALID"
    key = (row["path"], row["rule_id"])
    if (
        key in observed
        or row["path"] not in native_sources
        or row["rule_id"] not in lane["rule_ids"]
    ):
        return None, None, "RULE_NATIVE_LEDGER_UNBOUND"
    if not _native_counts_valid(row["counts"]):
        return None, None, "RULE_NATIVE_LEDGER_INVALID"
    return key, row["counts"], None


def _native_accounting_gaps(coverage, observed):
    account = coverage.get("rule_accounting")
    if not isinstance(account, dict) or not isinstance(account.get("rules"), list):
        return ["RULE_SOURCE_ACCOUNTING_MISSING"]
    binding_error = _native_accounting_binding_error(account, coverage)
    if binding_error:
        return [binding_error]
    for rule in account["rules"]:
        error = _native_accounting_rule(rule, coverage, observed)
        if error:
            return [error]
    return []


def _native_accounting_binding_error(account, coverage):
    if account.get("native_ledger_sha256") != coverage.get("native_rule_ledger_sha256"):
        return "RULE_ACCOUNTING_LEDGER_DRIFT"
    if account.get("native_source_inventory_sha256") != coverage.get(
        "native_source_inventory_sha256"
    ):
        return "RULE_ACCOUNTING_SOURCE_INVENTORY_DRIFT"
    return None


def _native_accounting_rule(rule, coverage, observed):
    if not isinstance(rule, dict) or not isinstance(rule.get("rule_id"), str):
        return "RULE_SOURCE_ACCOUNTING_MISSING"
    rows = rule.get("sources")
    if not isinstance(rows, list):
        return "RULE_SOURCE_ACCOUNTING_MISSING"
    for row in rows:
        error = _native_accounting_row(rule, row, coverage, observed)
        if error:
            return error
    return None


def _native_accounting_row(rule, row, coverage, observed):
    if not isinstance(row, dict) or not isinstance(row.get("path"), str):
        return "RULE_SOURCE_ACCOUNTING_MISSING"
    key = (row["path"], rule["rule_id"])
    native = observed.get(key, {})
    if row.get("native_counts") != native:
        return "RULE_NATIVE_LEDGER_ACCOUNTING_DRIFT"
    if row.get("disposition") != _native_counts_disposition(native):
        return "RULE_NATIVE_DISPOSITION_DRIFT"
    evidence = {
        "ledger_sha256": coverage["native_rule_ledger_sha256"],
        "source_sha256": row.get("source_sha256"),
        "path": row.get("path"),
        "rule_id": rule.get("rule_id"),
        "counts": native,
    }
    if row.get("evidence_sha256") != digest(evidence):
        return "RULE_SOURCE_EVIDENCE_DRIFT"
    return None


def _native_counts_disposition(counts):
    if any(key.startswith("suppressed_") for key in counts):
        return "suppressed"
    if counts.get("not_run_size_limit", 0):
        return "not_run"
    if counts.get("regex_executed", 0) or counts.get("path_evaluated", 0):
        return "executed"
    if counts.get("not_applicable_path_mismatch", 0) or counts.get(
        "not_applicable_no_regex", 0
    ):
        return "not_applicable"
    return "not_run"


def _rule_accounting_gaps(coverage, lane, required, report=None):
    if lane["engine"] == "semgrep" and "native_artifact_roles" in lane:
        return _semgrep_rule_execution_gaps(coverage, lane, required, report)
    if lane["engine"] != "gitleaks":
        return []
    gaps = _rule_inventory_gaps(coverage, lane)
    if gaps:
        return gaps
    accounting = coverage.get("rule_accounting")
    gaps = _rule_accounting_shape(accounting, lane, required)
    if gaps:
        return gaps
    gaps = _rule_accounting_binding_gaps(accounting, coverage, lane)
    if gaps:
        return gaps
    if report is None:
        return ["RULE_NATIVE_REPORT_REQUIRED"]
    gaps = _native_rule_ledger_gaps(coverage, lane, required, report)
    if gaps:
        return gaps
    return _rule_execution_matrix_gaps(accounting, lane, required)


def _semgrep_rule_execution_gaps(coverage, lane, required, report):
    from .deep_audit_io import verify_semgrep_rule_execution

    try:
        verify_semgrep_rule_execution(
            coverage.get("semgrep_rule_execution"), lane, required, report
        )
    except (RuntimeAuditError, ValueError, TypeError, KeyError, AttributeError):
        return ["SEMGREP_NATIVE_RULE_EXECUTION_UNVERIFIED"]
    return []


def _rule_accounting_binding_gaps(accounting, coverage, lane):
    if accounting["schema"] != "factory.deep-rule-accounting.v1":
        return ["RULE_ACCOUNTING_SCHEMA"]
    if accounting["ruleset_sha256"] != lane["ruleset_sha256"]:
        return ["RULESET_ACCOUNTING_DRIFT"]
    if accounting["rule_inventory_sha256"] != coverage["rule_inventory"]["sha256"]:
        return ["RULE_INVENTORY_ACCOUNTING_DRIFT"]
    if accounting["native_source_inventory_sha256"] != coverage.get(
        "native_source_inventory_sha256"
    ):
        return ["RULE_ACCOUNTING_SOURCE_INVENTORY_DRIFT"]
    for key in ("invocation_sha256", "native_report_sha256"):
        if accounting[key] != coverage.get(key):
            return ["RULE_ACCOUNTING_BINDING_DRIFT"]
        require_digest(accounting[key], key)
    body = {
        key: value for key, value in accounting.items() if key != "accounting_sha256"
    }
    if accounting["accounting_sha256"] != digest(body):
        return ["RULE_ACCOUNTING_HASH_DRIFT"]
    return []


def _rule_execution_matrix_gaps(accounting, lane, required):
    ids = [
        item.get("rule_id") for item in accounting["rules"] if isinstance(item, dict)
    ]
    if (
        len(ids) != len(accounting["rules"])
        or not all(isinstance(item, str) for item in ids)
        or set(ids) != set(lane["rule_ids"])
    ):
        return ["RULE_ACCOUNTING_INVENTORY_DRIFT"]
    gaps = []
    for rule in accounting["rules"]:
        rows = _rule_source_rows(rule, required)
        if rows is None:
            return ["RULE_SOURCE_ACCOUNTING_MISSING"]
        if any(value != "executed" for value in rows.values()):
            gaps.append("RULE_EXECUTION_INCOMPLETE")
    return gaps


def _coverage_tool_gaps(coverage, lane):
    gaps = []
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
    return gaps


def _coverage_gaps(report, coverage, lane, required, obligations):
    _native_accounting(report, lane, required)
    gaps = _coverage_source_gaps(report, coverage, lane, required)
    gaps.extend(_coverage_tool_gaps(coverage, lane))
    accounting_gaps = _rule_accounting_gaps(coverage, lane, required, report)
    if lane["engine"] == "gitleaks" and accounting_gaps:
        gaps.append("SECRETS_NATIVE_ACCOUNTING_UNAVAILABLE")
    gaps.extend(accounting_gaps)
    expected = _covered_obligation_ids(obligations, lane, required)
    observed = _list(coverage.get("obligations"), 0, 4096)
    if _obligation_coverage_missing(observed, expected):
        gaps.append("OBLIGATION_COVERAGE_MISSING")
    return gaps, expected, observed


def _covered_obligation_ids(obligations, lane, required):
    return {
        item["id"]
        for item in obligations
        if item["family"] == lane["family"]
        and item["engine"] == lane["engine"]
        and set(item["paths"]) <= set(required)
    }


def _obligation_coverage_missing(observed, expected):
    return (
        any(not isinstance(item, str) for item in observed)
        or set(observed) != expected
        or not expected
    )


def _approved_challenges(obligations, expected):
    return {
        (item["id"], challenge["kind"]): (challenge, item)
        for item in obligations
        if item["id"] in expected
        for challenge in item["challenges"]
    }


def _challenge_gap(challenge, identity, approved, lane, sources):
    try:
        for key in ("fixture_sha256", "observation_sha256"):
            require_digest(challenge.get(key), key)
    except RuntimeAuditError:
        return True
    bound_item = approved.get(identity)
    if bound_item is None or not isinstance(challenge.get("report"), dict):
        return True
    report_evidence = challenge["report"]
    report_digest = digest(report_evidence)
    bound, obligation = bound_item
    _challenge_semantics(report_evidence, lane, bound, obligation, identity[1], sources)
    source_binding_ok = _challenge_source_binding(bound, sources)
    return (
        challenge["fixture_sha256"] != bound["fixture_sha256"]
        or not source_binding_ok
        or report_digest != challenge["observation_sha256"]
        or report_digest != bound["expected_report_sha256"]
        or type(challenge.get("exit_code")) is not int
        or challenge["exit_code"] != bound["expected_exit_code"]
    )


def _challenge_source_binding(bound, sources):
    manifest = bound.get("fixture_manifest")
    if manifest is None:
        return sources.get(bound["fixture_path"]) == bound["fixture_sha256"]
    return all(sources.get(path) == source_sha for path, source_sha in manifest.items())


def _challenge_execution_gap(
    challenge, bound, obligation, identity, lane, coverage, candidate_sha
):
    if "fixture_manifest" in bound:
        return _challenge_execution_v2_gap(
            challenge, bound, obligation, identity, lane, coverage, candidate_sha
        )
    execution = challenge.get("execution")
    fields = {
        "schema",
        "status",
        "launched",
        "completed",
        "timed_out",
        "cleanup_confirmed",
        "scratch_cleanup_verified",
        "timeout_seconds",
        "duration_ms",
        "exit_code",
        "argv_sha256",
        "raw_report_sha256",
        "stdout_sha256",
        "stdout_bytes",
        "stderr_sha256",
        "stderr_bytes",
        "fixture_sha256",
        "candidate_binding_sha256",
        "challenge_source_sha256",
        "profile_binding_sha256",
        "image_binding_sha256",
        "tool_version",
        "version_probe_sha256",
        "baseline_config_sha256",
        "effective_config_sha256",
        "ledger_sha256",
        "mutation",
        "execution_sha256",
    }
    if not isinstance(execution, dict) or set(execution) != fields:
        return True
    return not _challenge_execution_fields_valid(
        execution, challenge, bound, obligation, identity, lane, coverage, candidate_sha
    )


def _challenge_execution_v2_gap(
    challenge, bound, obligation, identity, lane, coverage, candidate_sha
):
    execution = challenge.get("execution")
    fields = _challenge_execution_v2_fields()
    if not isinstance(execution, dict) or set(execution) != fields:
        return True
    return not _challenge_execution_v2_valid(
        execution, challenge, bound, obligation, identity, lane, coverage, candidate_sha
    )


def _challenge_execution_v2_fields():
    return {
        "schema",
        "status",
        "launched",
        "completed",
        "timed_out",
        "cleanup_confirmed",
        "scratch_cleanup_verified",
        "timeout_seconds",
        "duration_ms",
        "exit_code",
        "argv_sha256",
        "raw_report_sha256",
        "stdout_sha256",
        "stdout_bytes",
        "stderr_sha256",
        "stderr_bytes",
        "fixture_sha256",
        "fixture_manifest_sha256",
        "candidate_binding_sha256",
        "challenge_source_sha256",
        "profile_binding_sha256",
        "image_binding_sha256",
        "tool_version",
        "version_probe_sha256",
        "baseline_config_sha256",
        "effective_config_sha256",
        "ledger_sha256",
        "native_artifacts",
        "mutation",
        "execution_sha256",
    }


def _challenge_execution_v2_valid(
    execution, challenge, bound, obligation, identity, lane, coverage, candidate_sha
):
    if not _challenge_execution_v2_control(execution, bound):
        return False
    if not _challenge_execution_v2_artifacts(execution, lane):
        return False
    if not _challenge_execution_v2_binding(
        execution, bound, obligation, identity, lane, coverage, candidate_sha
    ):
        return False
    body = {key: value for key, value in execution.items() if key != "execution_sha256"}
    if execution.get("execution_sha256") != digest(body):
        return False
    return _challenge_execution_budgets_valid_v2(execution, lane)


def _challenge_execution_v2_control(execution, bound):
    return (
        execution.get("schema") == "factory.native-challenge-execution.v2"
        and execution.get("status") == "VERIFIED"
        and execution.get("launched") is True
        and execution.get("completed") is True
        and execution.get("timed_out") is False
        and execution.get("cleanup_confirmed") is True
        and execution.get("scratch_cleanup_verified") is True
        and type(execution.get("exit_code")) is int
        and execution["exit_code"] == bound["expected_exit_code"]
        and execution.get("fixture_sha256") == bound["fixture_sha256"]
        and execution.get("fixture_manifest_sha256") == bound["fixture_manifest_sha256"]
    )


def _challenge_execution_v2_artifacts(execution, lane):
    artifacts = execution.get("native_artifacts")
    roles = lane.get("native_artifact_roles")
    by_role = _native_artifact_record_map(artifacts, roles)
    if by_role is None:
        return False
    return _challenge_v2_artifact_bindings(execution, lane, by_role)


def _native_artifact_record_map(artifacts, roles):
    if not isinstance(artifacts, list) or not isinstance(roles, list):
        return None
    if len(artifacts) != len(roles):
        return None
    total = 0
    by_role = {}
    for artifact in artifacts:
        if not _native_artifact_record_valid(artifact, by_role):
            return None
        role = artifact["kind"]
        total += artifact["bytes"]
        by_role[role] = artifact
    if total > 8 * 1024 * 1024 or list(by_role) != sorted(roles):
        return None
    return by_role if set(by_role) == set(roles) else None


def _native_artifact_record_valid(artifact, by_role):
    if not isinstance(artifact, dict) or set(artifact) != {"kind", "sha256", "bytes"}:
        return False
    if not isinstance(artifact["kind"], str) or artifact["kind"] in by_role:
        return False
    try:
        require_digest(artifact["sha256"], "native artifact digest")
        require_int(
            artifact["bytes"],
            "native artifact bytes",
            minimum=0,
            maximum=8 * 1024 * 1024,
        )
    except RuntimeAuditError:
        return False
    return True


def _challenge_v2_artifact_bindings(execution, lane, by_role):
    report_role = _NATIVE_REPORT_ROLES.get(lane["engine"])
    if report_role is None or by_role[report_role]["sha256"] != execution.get(
        "raw_report_sha256"
    ):
        return False
    if lane["engine"] == "gitleaks":
        return (
            execution.get("ledger_sha256") == by_role["gitleaks_rule_ledger"]["sha256"]
        )
    if lane["engine"] == "semgrep" and not _semgrep_config_inventory_valid(
        execution, lane, by_role["rule_inventory"]
    ):
        return False
    return execution.get("ledger_sha256") is None


def _semgrep_config_inventory_valid(execution, lane, artifact):
    """Bind adapter-derived config inventory; it is not independent scanner evidence."""
    mutation = execution.get("mutation")
    disabled = mutation.get("disabled_rule_id") if isinstance(mutation, dict) else None
    rules = [rule for rule in lane["rule_ids"] if rule != disabled]
    inventory = {
        "ruleset_sha256": execution.get("effective_config_sha256"),
        "rule_ids": rules,
    }
    raw = canonical_bytes(inventory)
    return artifact["sha256"] == sha256_bytes(raw) and artifact["bytes"] == len(raw)


def _challenge_execution_v2_binding(
    execution, bound, obligation, identity, lane, coverage, candidate_sha
):
    expected_source = digest(bound["fixture_manifest"])
    expected_image = sha256_bytes(lane["image"].encode("utf-8"))
    return (
        execution.get("candidate_binding_sha256") == candidate_sha
        and execution.get("challenge_source_sha256") == expected_source
        and execution.get("profile_binding_sha256") == coverage.get("profile_sha256")
        and execution.get("image_binding_sha256") == expected_image
        and execution.get("tool_version") == lane["tool_version"]
        and execution.get("version_probe_sha256")
        == digest(coverage.get("version_probe"))
        and _challenge_execution_config_valid_v2(execution, obligation, identity, lane)
    )


def _challenge_execution_config_valid_v2(execution, obligation, identity, lane):
    expected_mutation = None
    if identity[1] == "mutation":
        mutation_hashes = lane.get("mutation_config_sha256")
        rule_id = obligation["detector_rule_id"]
        expected_effective = (
            mutation_hashes.get(rule_id) if isinstance(mutation_hashes, dict) else None
        )
        remaining = [rule for rule in lane["rule_ids"] if rule != rule_id]
        expected_mutation = {
            "disabled_rule_id": rule_id,
            "remaining_rule_inventory_sha256": digest(remaining),
        }
        if expected_effective is None:
            return False
    else:
        expected_effective = lane["ruleset_sha256"]
    return (
        execution.get("effective_config_sha256") == expected_effective
        and execution.get("baseline_config_sha256") == lane["ruleset_sha256"]
        and execution.get("mutation") == expected_mutation
    )


def _challenge_execution_budgets_valid_v2(execution, lane):
    try:
        for key in (
            "argv_sha256",
            "raw_report_sha256",
            "stdout_sha256",
            "stderr_sha256",
            "fixture_sha256",
            "fixture_manifest_sha256",
            "candidate_binding_sha256",
            "challenge_source_sha256",
            "profile_binding_sha256",
            "image_binding_sha256",
            "version_probe_sha256",
            "baseline_config_sha256",
            "effective_config_sha256",
            "execution_sha256",
        ):
            require_digest(execution.get(key), key)
        if execution.get("ledger_sha256") is not None:
            require_digest(execution["ledger_sha256"], "ledger_sha256")
        require_int(
            execution.get("timeout_seconds"),
            "challenge timeout",
            minimum=1,
            maximum=lane["timeout_seconds"],
        )
        require_int(
            execution.get("duration_ms"),
            "challenge duration",
            minimum=0,
            maximum=execution["timeout_seconds"] * 1000,
        )
        for key in ("stdout_bytes", "stderr_bytes"):
            require_int(execution.get(key), key, minimum=0, maximum=8 * 1024 * 1024)
    except RuntimeAuditError:
        return False
    return True


def _challenge_execution_fields_valid(
    execution, challenge, bound, obligation, identity, lane, coverage, candidate_sha
):
    if not _challenge_execution_control_valid(execution, bound):
        return False
    if not _challenge_execution_binding_valid(
        execution, bound, obligation, identity, lane, coverage, candidate_sha
    ):
        return False
    body = {key: value for key, value in execution.items() if key != "execution_sha256"}
    if execution.get("execution_sha256") != digest(body):
        return False
    return _challenge_execution_budgets_valid(execution, bound, lane, identity)


def _challenge_execution_control_valid(execution, bound):
    return (
        execution.get("schema") == "factory.native-challenge-execution.v1"
        and execution.get("status") == "VERIFIED"
        and execution.get("launched") is True
        and execution.get("completed") is True
        and execution.get("timed_out") is False
        and execution.get("cleanup_confirmed") is True
        and execution.get("scratch_cleanup_verified") is True
        and type(execution.get("exit_code")) is int
        and execution["exit_code"] == bound["expected_exit_code"]
        and execution.get("fixture_sha256") == bound["fixture_sha256"]
    )


def _challenge_execution_binding_valid(
    execution, bound, obligation, identity, lane, coverage, candidate_sha
):
    expected_source = digest({bound["fixture_path"]: bound["fixture_sha256"]})
    expected_image = sha256_bytes(lane["image"].encode("utf-8"))
    return _challenge_execution_identity_valid(
        execution, bound, lane, coverage, candidate_sha, expected_source, expected_image
    ) and _challenge_execution_config_valid(
        execution, bound, obligation, identity, lane
    )


def _challenge_execution_identity_valid(
    execution, bound, lane, coverage, candidate_sha, expected_source, expected_image
):
    return (
        execution.get("candidate_binding_sha256") == candidate_sha
        and execution.get("challenge_source_sha256") == expected_source
        and execution.get("profile_binding_sha256") == coverage.get("profile_sha256")
        and execution.get("image_binding_sha256") == expected_image
        and execution.get("tool_version") == lane["tool_version"]
        and execution.get("version_probe_sha256")
        == digest(coverage.get("version_probe"))
    )


def _challenge_execution_config_valid(execution, bound, obligation, identity, lane):
    expected_mutation = None
    if identity[1] == "mutation":
        mutation_hashes = lane.get("mutation_config_sha256")
        expected_effective = (
            mutation_hashes.get(obligation["detector_rule_id"])
            if isinstance(mutation_hashes, dict)
            else None
        )
        remaining = sorted(
            rule
            for rule in lane.get("rule_ids", [])
            if rule != obligation["detector_rule_id"]
        )
        expected_mutation = {
            "disabled_rule_id": obligation["detector_rule_id"],
            "remaining_rule_inventory_sha256": digest(remaining),
        }
        if expected_effective is None:
            return False
    else:
        expected_effective = lane["ruleset_sha256"]
    return (
        execution.get("effective_config_sha256") == expected_effective
        and execution.get("baseline_config_sha256") == lane["ruleset_sha256"]
        and execution.get("mutation") == expected_mutation
    )


def _challenge_execution_budgets_valid(execution, bound, lane, identity):
    try:
        for key in (
            "argv_sha256",
            "raw_report_sha256",
            "stdout_sha256",
            "stderr_sha256",
            "challenge_source_sha256",
            "profile_binding_sha256",
            "image_binding_sha256",
            "version_probe_sha256",
            "baseline_config_sha256",
            "effective_config_sha256",
            "ledger_sha256",
            "execution_sha256",
        ):
            require_digest(execution.get(key), key)
        require_int(
            execution.get("timeout_seconds"),
            "challenge timeout",
            minimum=1,
            maximum=lane["timeout_seconds"],
        )
        require_int(
            execution.get("duration_ms"),
            "challenge duration",
            minimum=0,
            maximum=execution["timeout_seconds"] * 1000,
        )
        for key in ("stdout_bytes", "stderr_bytes"):
            require_int(execution.get(key), key, minimum=0, maximum=8 * 1024 * 1024)
    except RuntimeAuditError:
        return False
    if identity[1] == "mutation":
        return (
            execution["effective_config_sha256"] != execution["baseline_config_sha256"]
        )
    return execution["effective_config_sha256"] == execution["baseline_config_sha256"]


def _challenge_gaps(
    challenges, lane, sources, obligations, expected, coverage, candidate_sha
):
    if challenges.get("schema") != "factory.deep-challenges.v1":
        raise RuntimeAuditError("E_CHALLENGE_SCHEMA", "expected challenge observations")
    seen = set()
    approved = _approved_challenges(obligations, expected)
    gaps = []
    for challenge in _list(challenges.get("observations"), 0, 8192):
        identity = (
            require_str(challenge.get("obligation_id"), "obligation"),
            _enum(challenge.get("kind"), {"positive", "negative", "mutation"}),
        )
        if identity in seen:
            raise RuntimeAuditError("E_CHALLENGE_DUPLICATE", "duplicate challenge")
        seen.add(identity)
        if _challenge_gap(challenge, identity, approved, lane, sources):
            gaps.append("CHALLENGE_FAILED")
        elif (
            lane["engine"] == "gitleaks" or _is_v2_obligation(identity, approved)
        ) and _challenge_execution_gap(
            challenge,
            approved[identity][0],
            approved[identity][1],
            identity,
            lane,
            coverage,
            candidate_sha,
        ):
            gaps.append("CHALLENGE_FAILED")
    required = {
        (identity, kind)
        for identity in expected
        for kind in ("positive", "negative", "mutation")
    }
    if seen != required:
        gaps.append("CHALLENGE_COVERAGE_MISSING")
    return gaps


def _is_v2_obligation(identity, approved):
    item = approved.get(identity)
    return item is not None and "fixture_manifest" in item[0]


def normalize_execution_bundle(
    bundle: dict, lane: dict, inventory: dict, run_id: str, obligations: list
) -> dict:
    """Check bounded worker evidence. Coverage remains an independently reviewed claim."""
    report, coverage, challenges, sources = _worker_artifacts(
        bundle, lane, inventory, run_id
    )
    required = _required_sources(inventory, lane)
    findings = _native_execution_report(report, lane, sources)
    gaps, expected, observed = _coverage_gaps(
        report, coverage, lane, required, obligations
    )
    gaps.extend(
        _challenge_gaps(
            challenges,
            lane,
            sources,
            obligations,
            expected,
            coverage,
            inventory["candidate_sha256"],
        )
    )
    metrics = None
    if lane["family"] in {"runtime", "fuzz"}:
        metric_keys = (
            ("executions", "coverage_edges", "corpus_size")
            if lane["family"] == "fuzz"
            else ("requests",)
            if lane["engine"] == "zap"
            else ("tests",)
        )
        metrics = {key: report["metrics"][key] for key in metric_keys}
    return {
        "lane_id": lane["id"],
        "engine": lane["engine"],
        "family": lane["family"],
        "state": "INCOMPLETE" if gaps else "OBSERVED",
        "gaps": sorted(set(gaps)),
        "report_sha256": digest(report),
        "coverage_sha256": digest(coverage),
        "rule_accounting_sha256": (
            coverage.get("rule_accounting", {}).get("accounting_sha256")
            if isinstance(coverage.get("rule_accounting"), dict)
            else None
        ),
        "challenge_sha256": digest(challenges),
        "covered_paths": sorted(required),
        "obligations": observed,
        "findings": findings,
        "metrics": metrics,
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
            if (
                not isinstance(value, str)
                or len(value) > 1024
                or any(ord(character) < 32 for character in value)
            ):
                raise RuntimeAuditError(
                    "E_FIELD", "fingerprint must be a bounded printable string"
                )
            native[group + ":" + name] = value
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
    native_fingerprint_sha256 = digest(native)
    identity_basis = "sarif_native_fingerprint"
    identity_native = native
    if not any(value.strip() for value in native.values()):
        identity_basis = "source_location_fallback"
        identity_native = {
            "native_fingerprint_sha256": native_fingerprint_sha256,
            "locations_sha256": digest(locations),
        }
    suppressions = _suppression(result)
    return {
        "finding_id": digest(
            {
                "schema": "factory.deep-finding-identity.v1",
                "analyzer": analyzer["id"],
                "rule": rule,
                "native": identity_native,
            }
        ),
        "native_fingerprint_sha256": native_fingerprint_sha256,
        "finding_identity_basis": identity_basis,
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
