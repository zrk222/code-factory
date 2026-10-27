"""Strict SARIF subset with native identities and source-bound ordered flow evidence.

This parser does not verify signer authority, execute scanners, or decide release.
Unrecognized SARIF indirection is rejected rather than silently dropping evidence.
"""

from __future__ import annotations

from . import deep_audit_io as _deep_audit_io
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

_ZAP_LEDGER_BYTES = 4 * 1024 * 1024
_ZAP_LEDGER_RECORD_BYTES = 4096
_ZAP_LEDGER_RECORDS = 100_000
_ZAP_LEDGER_COUNT_MAX = 1_000_000
_ZAP_LEDGER_EVENTS = {
    "invocation_started": ("started", "invocation"),
    "invocation_returned": ("returned", "invocation"),
    "invocation_failed": ("failed", "invocation_failure"),
    "plugin_completed": ("completed", "plugin_terminal"),
    "plugin_failed": ("failed", "plugin_terminal"),
    "plugin_skipped": ("skipped", "plugin_terminal"),
    "plugin_stopped": ("stopped", "plugin_terminal"),
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
        minimum = 0 if lane.get("mode") == "offline-pypi-snapshot" else 1
        for package in _list(result.get("packages"), minimum, 20_000):
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


def _osv_challenge_rows(report, lane, sources, obligation, kind):
    """Check native package/advisory semantics; this is not execution authority."""
    if kind not in {"positive", "negative", "mutation"}:
        raise RuntimeAuditError("E_OSV_CHALLENGE", "unknown OSV control kind")
    account = _osv_source_accounting(report, sources, lane["mode"])
    if account["state"] != "COMPLETE":
        raise RuntimeAuditError(
            "E_OSV_CHALLENGE", "complete manifest reporting required"
        )
    _execution_osv(report, lane, sources)
    target = obligation["osv_target"]
    control = next(item for item in obligation["challenges"] if item["kind"] == kind)
    anchor = relative_path(control["fixture_path"])
    version = target["fixed_version" if kind == "negative" else "vulnerable_version"]
    expected = {"name": target["package"], "version": version, "ecosystem": "PyPI"}
    packages = account["sources"].get(anchor, {}).get("packages", [])
    if sum(item == expected for item in packages) != 1:
        raise RuntimeAuditError(
            "E_OSV_CHALLENGE", "signed target package/version absent"
        )
    rows = _osv_challenge_finding_rows(report, anchor, expected, target["aliases"])
    targeted, unrelated, observed_aliases = rows
    if kind == "positive":
        if not targeted or observed_aliases != set(target["aliases"]):
            raise RuntimeAuditError(
                "E_OSV_CHALLENGE", "positive advisory family differs"
            )
    elif targeted:
        raise RuntimeAuditError("E_OSV_CHALLENGE", "target advisory survived control")
    inventory = [
        {"path": path, **package}
        for path, source in sorted(account["sources"].items())
        for package in source["packages"]
    ]
    return {
        "schema": "factory.osv-challenge-rows.v1",
        "inventory": sorted(inventory, key=canonical_bytes),
        "target_rows": sorted(targeted, key=canonical_bytes),
        "unrelated_rows": sorted(unrelated, key=canonical_bytes),
        "report_sha256": digest(report),
    }


def _osv_challenge_finding_rows(report, anchor, expected, aliases):
    targeted, unrelated, observed_aliases = [], [], set()
    for result in report["results"]:
        path = result["source"]["path"]
        for package in result["packages"]:
            identity = package["package"]
            for advisory in package.get("vulnerabilities", []):
                family = {advisory["id"], *advisory.get("aliases", [])}
                row = {
                    "path": path,
                    "package": {key: identity[key] for key in expected},
                    "advisory_id": advisory["id"],
                    "aliases": sorted(advisory.get("aliases", [])),
                    "advisory_sha256": digest(advisory),
                }
                if (
                    path == anchor
                    and row["package"] == expected
                    and family.intersection(aliases)
                ):
                    if not family <= set(aliases):
                        raise RuntimeAuditError(
                            "E_OSV_CHALLENGE", "unsigned advisory alias"
                        )
                    targeted.append(row)
                    observed_aliases.update(family)
                else:
                    unrelated.append(row)
    return targeted, unrelated, observed_aliases


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
        require_int(
            metrics.get(key),
            key,
            minimum=0 if key == "coverage_edges" else 1,
            maximum=10**12,
        )


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


def _osv_source_accounting(report, required, mode):
    """Bind observed manifest/package reporting, not undisclosed dependency completeness."""
    report = _object(report)
    if report.get("errors") or report.get("error"):
        raise RuntimeAuditError("E_DEPENDENCY_ERRORS", "OSV analysis errors remain")
    sources = {}
    errors = set()
    for result in _list(report.get("results"), 0, 20_000):
        result = _object(result)
        path = relative_path(_object(result.get("source")).get("path"))
        if path not in required or path in sources:
            raise RuntimeAuditError(
                "E_DEPENDENCY_COVERAGE", "OSV manifest is duplicate or unbound"
            )
        packages = _osv_accounting_packages(result)
        errors.update(_osv_package_scope_errors(packages, mode))
        sources[path] = {
            "sha256": require_digest(required[path], "manifest hash"),
            "package_count": len(packages),
            "packages_sha256": digest(packages),
            "packages": packages,
        }
    accounting = _osv_accounting_result(report, required, sources, errors)
    if "factory_lookup_execution" in report:
        accounting["lookup_execution"] = _osv_lookup_execution(report, sources)
    return accounting


def _osv_lookup_fields(value, fields):
    value = _object(value)
    if set(value) != set(fields.split()):
        raise RuntimeAuditError("E_OSV_LOOKUPS", "native lookup fields differ")
    return value


def _osv_lookup_targets(report):
    targets = {}
    for result in report["results"]:
        path = result["source"]["path"]
        for row in result["packages"]:
            key = canonical_bytes(
                {
                    field: row["package"][field]
                    for field in ("name", "version", "ecosystem")
                }
            )
            target = targets.setdefault(key, {"locations": set(), "matched": set()})
            target["locations"].add(path)
            target["matched"].update(
                require_str(_object(item).get("id"), "advisory id", maximum=256)
                for item in _list(row.get("vulnerabilities", []), 0, 20_000)
            )
    return targets


def _osv_lookup_extractors(runs):
    for run in _list(runs, 1, 1024):
        run = _osv_lookup_fields(run, "plugins statuses")
        plugins = _list(run["plugins"], 1, 1024)
        for name in plugins:
            require_str(name, "extractor name", maximum=256)
        statuses = _list(run["statuses"], 1, 1024)
        names = []
        for row in statuses:
            row = _osv_lookup_fields(row, "name state")
            names.append(require_str(row["name"], "extractor name", maximum=256))
            if row["state"] != "SUCCEEDED":
                raise RuntimeAuditError("E_OSV_LOOKUPS", "extractor did not succeed")
        if plugins != sorted(set(plugins)) or sorted(names) != plugins:
            raise RuntimeAuditError("E_OSV_LOOKUPS", "extractor execution set differs")


def _osv_lookup_query(row, ledger, targets):
    row = _osv_lookup_fields(
        row,
        "name version ecosystem locations state evaluated_advisories "
        "evaluated_sha256 decision_sha256 matched_advisories",
    )
    identity = {
        key: require_str(row[key], f"query.{key}", maximum=256)
        for key in ("name", "version", "ecosystem")
    }
    key = canonical_bytes(identity)
    if key not in targets or row["state"] != "EXECUTED":
        raise RuntimeAuditError("E_OSV_LOOKUPS", "query is unbound or did not execute")
    paths = [relative_path(path) for path in _list(row["locations"], 1, 20_000)]
    matched = _list(row["matched_advisories"], 0, 20_000)
    for advisory in matched:
        require_str(advisory, "matched advisory", maximum=256)
    evaluated = require_int(
        row["evaluated_advisories"], "evaluated advisories", minimum=1, maximum=10**6
    )
    expected_decision = digest(
        {
            **identity,
            "catalog_sha256": ledger["catalog_sha256"],
            "evaluated_advisories": evaluated,
            "matched_advisories": matched,
        }
    )
    if require_digest(row["decision_sha256"], "decision hash") != expected_decision:
        raise RuntimeAuditError("E_OSV_LOOKUPS", "native decision hash differs")
    if (
        paths != sorted(targets[key]["locations"])
        or matched != sorted(targets[key]["matched"])
        or evaluated != ledger["catalog_advisories"]
        or row["evaluated_sha256"] != ledger["catalog_sha256"]
    ):
        raise RuntimeAuditError("E_OSV_LOOKUPS", "query decisions or input set differ")
    return key, row


def _osv_lookup_execution(report, sources):
    ledger = _osv_lookup_fields(
        report["factory_lookup_execution"],
        "schema upstream_commit database_sha256 catalog_advisories catalog_sha256 "
        "queries extractor_runs",
    )
    if (
        ledger["schema"] != "factory.osv-lookup-execution.v1"
        or ledger["upstream_commit"] != "a14aa98ab8408547083d4411091c5fbaf5b47d8e"
    ):
        raise RuntimeAuditError("E_OSV_LOOKUPS", "unrecognized native lookup producer")
    require_digest(ledger["database_sha256"], "lookup database hash")
    require_digest(ledger["catalog_sha256"], "advisory catalog hash")
    require_int(ledger["catalog_advisories"], "catalog size", minimum=1, maximum=10**6)
    _osv_lookup_extractors(ledger["extractor_runs"])
    targets = _osv_lookup_targets(report)
    observed = {}
    for row in _list(ledger["queries"], 1, 20_000):
        key, row = _osv_lookup_query(row, ledger, targets)
        if key in observed:
            raise RuntimeAuditError("E_OSV_LOOKUPS", "duplicate native package query")
        observed[key] = row
    if set(observed) != set(targets):
        raise RuntimeAuditError(
            "E_OSV_LOOKUPS", "package queries were not all executed"
        )
    return {
        **ledger,
        "queries": [observed[key] for key in sorted(observed)],
        "source_sha256": {path: row["sha256"] for path, row in sorted(sources.items())},
    }


def _osv_lookup_binding_gaps(report, lane):
    ledger = report.get("factory_lookup_execution")
    if ledger is None:
        return ["OSV_NATIVE_LOOKUPS_REQUIRED"]
    ledger = _object(ledger)
    expected = lane.get("native_policy", {}).get("database_sha256")
    if not expected or ledger.get("database_sha256") != expected:
        return ["OSV_NATIVE_LOOKUP_DATABASE_DRIFT"]
    return []


def _osv_accounting_packages(result):
    packages = []
    for row in _list(result.get("packages"), 0, 20_000):
        identity = _object(_object(row).get("package"))
        packages.append(
            {
                key: require_str(identity.get(key), f"package.{key}", maximum=256)
                for key in ("name", "version", "ecosystem")
            }
        )
    return sorted(packages, key=lambda item: canonical_bytes(item))


def _osv_package_scope_errors(packages, mode):
    errors = set()
    if not packages:
        errors.add("EMPTY_PACKAGE_INVENTORY")
    if mode == "offline-pypi-snapshot" and any(
        item["ecosystem"] != "PyPI" for item in packages
    ):
        errors.add("UNSUPPORTED_ECOSYSTEM")
    return errors


def _osv_accounting_result(report, required, sources, errors):
    missing = sorted(set(required) - set(sources))
    if missing:
        errors.add("MISSING_MANIFESTS")
    state = "INCOMPLETE" if errors else "COMPLETE"
    if not sources:
        state = "UNAVAILABLE"
    elif missing:
        state = "PARTIAL"
    return {
        "schema": "factory.osv-source-accounting.v1",
        "scope": "native_manifest_package_reporting",
        "state": state,
        "required_paths": sorted(required),
        "measured_paths": sorted(sources),
        "missing_paths": missing,
        "sources": sources,
        "report_sha256": digest(report),
        "errors": sorted(errors),
    }


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
        if lane["mode"] == "offline-pypi-snapshot":
            _osv_source_accounting(report, required, lane["mode"])
            return
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
    if lane["engine"] == "osv" and "fixture_manifest" in bound:
        _osv_challenge_rows(native, lane, bound["fixture_manifest"], obligation, kind)
        return
    if lane["engine"] == "atheris" and "fixture_manifest" in bound:
        _atheris_challenge_semantics(native, lane, bound, obligation, kind)
        return
    findings = _native_execution_report(native, lane, sources)
    _challenge_findings_valid(findings, native, lane, obligation, kind)


def _atheris_challenge_semantics(native, lane, bound, obligation, kind):
    rule = obligation["detector_rule_id"]
    config_sha = (
        lane["mutation_config_sha256"][rule]
        if kind == "mutation"
        else lane["ruleset_sha256"]
    )
    expected = {
        "schema": "factory.atheris-challenge-observation.v1",
        "kind": kind,
        "control_sha256": config_sha,
        "harness": {"path": bound["fixture_path"], "sha256": bound["fixture_sha256"]},
        "findings": (
            [{"rule_id": rule, "path": bound["fixture_path"], "severity": "high"}]
            if kind == "positive"
            else []
        ),
    }
    if rule != "FUZZ_EXCEPTION" or native != expected:
        raise RuntimeAuditError(
            "E_CHALLENGE_SEMANTICS", "signed fuzz control result differs"
        )


def _challenge_findings_valid(findings, native, lane, obligation, kind):
    rules = {item["rule_id"] for item in findings if not item["suppressed"]}
    if lane["engine"] == "syft":
        rules = {item["id"] for item in native["artifacts"]}
    detected = obligation["detector_rule_id"] in rules
    clean_negative_failed = (
        lane["engine"] in {"gitleaks", "semgrep", "trivy"}
        and kind == "negative"
        and bool(rules)
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
    if lane["engine"] == "osv" and lane["mode"] == "offline-pypi-snapshot":
        expected = _osv_source_accounting(report, required, lane["mode"])
        gaps.extend(_osv_lookup_binding_gaps(report, lane))
        if expected["state"] != "COMPLETE":
            gaps.append("OSV_SOURCE_ACCOUNTING_INCOMPLETE")
        if canonical_bytes(coverage.get("source_accounting")) != canonical_bytes(
            expected
        ):
            gaps.append("OSV_SOURCE_ACCOUNTING_DRIFT")
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
    if lane["engine"] == "zap":
        return ["ZAP_NATIVE_RULE_EXECUTION_REQUIRED"]
    if lane["engine"] == "codeql":
        return _codeql_retained_evidence_gaps(coverage, lane, required)
    if lane["engine"] == "semgrep" and "native_artifact_roles" in lane:
        return _semgrep_rule_execution_gaps(coverage, lane, required, report)
    if lane["engine"] == "trivy" and "native_artifact_roles" in lane:
        return _trivy_rule_execution_gaps(coverage, lane, required, report)
    if lane["engine"] != "gitleaks":
        return []
    return _gitleaks_rule_accounting_gaps(coverage, lane, required, report)


def _verify_zap_native_rule_ledger(raw: bytes, lane: dict, bindings: dict) -> dict:
    """Validate bounded native ZAP plugin lifecycle records against signed bindings."""
    if not isinstance(raw, bytes) or len(raw) > _ZAP_LEDGER_BYTES:
        raise RuntimeAuditError("E_ZAP_LEDGER_SIZE", "ledger byte budget exceeded")
    if not isinstance(lane, dict) or lane.get("engine") != "zap":
        raise RuntimeAuditError("E_ZAP_LEDGER_LANE", "ZAP lane required")
    if not raw or not raw.endswith(b"\n"):
        raise RuntimeAuditError(
            "E_ZAP_LEDGER_JSONL", "newline-terminated records required"
        )
    lines = raw[:-1].split(b"\n")
    if not 1 <= len(lines) <= _ZAP_LEDGER_RECORDS or any(not line for line in lines):
        raise RuntimeAuditError("E_ZAP_LEDGER_SIZE", "ledger record budget exceeded")
    if any(len(line) > _ZAP_LEDGER_RECORD_BYTES for line in lines):
        raise RuntimeAuditError(
            "E_ZAP_LEDGER_SIZE", "ledger record byte budget exceeded"
        )
    _zap_exact_keys(
        bindings, {"run_id", "candidate_sha256", "profile_sha256", "host_id"}
    )
    _zap_ledger_bindings(bindings)
    expected_plugins = _zap_ledger_plugins(lane)
    plugin_state = {
        plugin_id: {"name": None, "terminal": None, "started": {}, "returned": set()}
        for plugin_id in expected_plugins
    }
    for line in lines:
        _zap_ledger_record(line, bindings, plugin_state)
    _zap_ledger_complete(plugin_state)
    return {
        "schema": "factory.zap-rule-verification.v1",
        "state": "VERIFIED",
        **bindings,
        "plugin_ids": expected_plugins,
        "invocation_count": sum(
            len(state["returned"]) for state in plugin_state.values()
        ),
        "plugin_count": len(expected_plugins),
        "ledger_sha256": sha256_bytes(raw),
    }


def _zap_ledger_bindings(bindings):
    run_id = require_str(bindings["run_id"], "run_id", maximum=128)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id) is None:
        raise RuntimeAuditError("E_ZAP_LEDGER_BINDING", "run_id is not canonical")
    for name in ("candidate_sha256", "profile_sha256", "host_id"):
        require_digest(bindings[name], name)


def _zap_ledger_plugins(lane):
    rule_ids = lane.get("rule_ids")
    if not isinstance(rule_ids, list) or not rule_ids or len(rule_ids) > 4096:
        raise RuntimeAuditError(
            "E_ZAP_LEDGER_INVENTORY", "enabled plugin inventory required"
        )
    plugin_ids = []
    for rule_id in rule_ids:
        if (
            not isinstance(rule_id, str)
            or re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", rule_id) is None
        ):
            raise RuntimeAuditError(
                "E_ZAP_LEDGER_INVENTORY", "numeric plugin IDs required"
            )
        plugin_ids.append(int(rule_id))
    if rule_ids != sorted(set(rule_ids)):
        raise RuntimeAuditError(
            "E_ZAP_LEDGER_INVENTORY", "sorted unique plugin inventory required"
        )
    return sorted(plugin_ids)


def _zap_ledger_record(line, bindings, plugin_state):
    row = strict_json(line)
    event = row.get("event")
    if not isinstance(event, str) or event not in _ZAP_LEDGER_EVENTS:
        raise RuntimeAuditError("E_ZAP_LEDGER_EVENT", "unknown ledger event")
    status, kind = _ZAP_LEDGER_EVENTS[event]
    fields = {
        "schema",
        "run_id",
        "candidate_sha256",
        "profile_sha256",
        "host_id",
        "plugin_id",
        "plugin_name",
        "invocation",
        "status",
        "event",
        "message_count",
        "alert_count",
    }
    if kind == "invocation_failure":
        fields.add("exception_class")
    _zap_exact_keys(row, fields)
    _zap_ledger_record_binding(row, bindings, status)
    plugin_id = require_int(
        row["plugin_id"], "plugin_id", minimum=0, maximum=2_147_483_647
    )
    if plugin_id not in plugin_state:
        raise RuntimeAuditError("E_ZAP_LEDGER_PLUGIN", "undeclared plugin ID")
    state = plugin_state[plugin_id]
    name = require_str(row["plugin_name"], "plugin_name", maximum=200)
    if not _zap_plugin_name_valid(name) or (
        state["name"] is not None and state["name"] != name
    ):
        raise RuntimeAuditError(
            "E_ZAP_LEDGER_PLUGIN", "plugin name is invalid or changed"
        )
    state["name"] = name
    require_int(
        row["message_count"], "message_count", minimum=0, maximum=_ZAP_LEDGER_COUNT_MAX
    )
    require_int(
        row["alert_count"], "alert_count", minimum=0, maximum=_ZAP_LEDGER_COUNT_MAX
    )
    if kind == "invocation":
        _zap_ledger_invocation(row, state, event)
    elif kind == "invocation_failure":
        require_str(row["exception_class"], "exception_class", maximum=256)
        _zap_ledger_invocation(row, state, event)
        raise RuntimeAuditError("E_ZAP_LEDGER_FAILURE", "plugin invocation failed")
    else:
        _zap_ledger_terminal(row, state, event)


def _zap_ledger_record_binding(row, bindings, status):
    if row.get("schema") != "factory.zap-rule-ledger.v1" or row.get("status") != status:
        raise RuntimeAuditError(
            "E_ZAP_LEDGER_BINDING", "ledger schema or event status differs"
        )
    if any(row.get(key) != value for key, value in bindings.items()):
        raise RuntimeAuditError(
            "E_ZAP_LEDGER_BINDING", "ledger execution binding differs"
        )


def _zap_exact_keys(value, expected):
    if not isinstance(value, dict) or set(value) != expected:
        raise RuntimeAuditError("E_ZAP_LEDGER_FIELDS", "ledger fields differ")


def _zap_plugin_name_valid(name):
    return re.fullmatch(r"[A-Za-z0-9._-]{1,128}", name) is not None


def _zap_ledger_invocation(row, state, event):
    invocation = require_int(
        row["invocation"], "invocation", minimum=1, maximum=_ZAP_LEDGER_RECORDS
    )
    if state["terminal"] is not None:
        raise RuntimeAuditError(
            "E_ZAP_LEDGER_ORDER", "plugin event follows terminal event"
        )
    if event == "invocation_started":
        if invocation in state["started"]:
            raise RuntimeAuditError("E_ZAP_LEDGER_ORDER", "duplicate invocation start")
        state["started"][invocation] = True
        return
    if invocation not in state["started"] or invocation in state["returned"]:
        raise RuntimeAuditError(
            "E_ZAP_LEDGER_ORDER", "invocation return has no unique start"
        )
    if event == "invocation_returned":
        state["returned"].add(invocation)


def _zap_ledger_terminal(row, state, event):
    if (
        require_int(row["invocation"], "invocation", minimum=0, maximum=0) != 0
        or state["terminal"] is not None
    ):
        raise RuntimeAuditError(
            "E_ZAP_LEDGER_ORDER", "plugin terminal event is duplicated or malformed"
        )
    if event != "plugin_completed":
        raise RuntimeAuditError("E_ZAP_LEDGER_FAILURE", "plugin did not complete")
    if row["message_count"] == 0:
        raise RuntimeAuditError(
            "E_ZAP_LEDGER_INCOMPLETE", "plugin has no request messages"
        )
    state["terminal"] = event


def _zap_ledger_complete(plugin_state):
    if any(
        state["terminal"] != "plugin_completed"
        or not state["started"]
        or set(state["started"]) != state["returned"]
        or sorted(state["started"]) != list(range(1, len(state["started"]) + 1))
        for state in plugin_state.values()
    ):
        raise RuntimeAuditError(
            "E_ZAP_LEDGER_INCOMPLETE", "plugin execution evidence is incomplete"
        )


def _gitleaks_rule_accounting_gaps(coverage, lane, required, report):
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


def _codeql_retained_evidence_gaps(coverage, lane, required):
    from .deep_audit_io import verify_codeql_retained_evidence

    try:
        verify_codeql_retained_evidence(coverage, lane, required)
    except (RuntimeAuditError, ValueError, TypeError, KeyError, AttributeError):
        return ["CODEQL_NATIVE_ARTIFACTS_UNVERIFIED"]
    return ["CODEQL_NATIVE_REPLAY_REQUIRED"]


def _osv_retained_evidence_gaps(
    coverage, lane, required, report, challenges, obligations
):
    from .deep_audit_io import verify_osv_retained_evidence

    if lane["engine"] != "osv":
        return []
    try:
        verify_osv_retained_evidence(
            coverage, lane, required, report, challenges, obligations
        )
    except (RuntimeAuditError, ValueError, TypeError, KeyError, AttributeError):
        return ["OSV_NATIVE_ARTIFACTS_UNVERIFIED"]
    return ["OSV_NATIVE_REPLAY_REQUIRED"]


def _fuzz_retained_evidence_gaps(report, lane, sources):
    from .deep_audit_io import _retained_fuzz_corpus

    if lane["engine"] != "atheris":
        return []
    try:
        _retained_fuzz_corpus(report, sources)
    except (RuntimeAuditError, ValueError, TypeError, KeyError, AttributeError):
        return ["FUZZ_NATIVE_CORPUS_UNVERIFIED"]
    return ["FUZZ_NATIVE_REPLAY_REQUIRED"]


def _semgrep_rule_execution_gaps(coverage, lane, required, report):
    from .deep_audit_io import verify_semgrep_rule_execution

    try:
        verify_semgrep_rule_execution(
            coverage.get("semgrep_rule_execution"), lane, required, report
        )
    except (RuntimeAuditError, ValueError, TypeError, KeyError, AttributeError):
        return ["SEMGREP_NATIVE_RULE_EXECUTION_UNVERIFIED"]
    return []


def _trivy_rule_execution_gaps(coverage, lane, required, report):
    from .deep_audit_io import verify_trivy_rule_execution

    try:
        verify_trivy_rule_execution(
            coverage.get("trivy_rule_execution"), lane, required, report
        )
    except (RuntimeAuditError, ValueError, TypeError, KeyError, AttributeError):
        return ["TRIVY_NATIVE_RULE_EXECUTION_UNVERIFIED"]
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
    return (
        _challenge_execution_budgets_valid_v2(execution, lane)
        and _trivy_challenge_native_valid(execution, challenge, bound, obligation, lane)
        and _codeql_challenge_native_valid(
            execution, challenge, bound, obligation, identity, lane, coverage
        )
        and _osv_challenge_native_valid(challenge, bound, obligation, identity, lane)
    )


def _osv_challenge_native_valid(challenge, bound, obligation, identity, lane):
    if lane["engine"] != "osv":
        return True
    from .deep_audit_io import verify_osv_retained_challenge

    try:
        verify_osv_retained_challenge(challenge, lane, bound, obligation, identity[1])
        return True
    except (RuntimeAuditError, ValueError, TypeError, KeyError, AttributeError):
        return False


def _trivy_challenge_native_valid(execution, challenge, bound, obligation, lane):
    if lane["engine"] != "trivy":
        return True
    from .deep_audit_io import verify_trivy_rule_execution

    try:
        evidence = challenge.get("trivy_rule_execution")
        mutation = execution.get("mutation")
        disabled = obligation["detector_rule_id"] if mutation is not None else None
        verify_trivy_rule_execution(
            evidence,
            lane,
            bound["fixture_manifest"],
            challenge["report"]["native_report"],
            disabled_rule_id=disabled,
        )
        return _trivy_challenge_artifacts_match(execution, evidence)
    except (RuntimeAuditError, ValueError, TypeError, KeyError, AttributeError):
        return False


def _codeql_challenge_native_valid(
    execution, challenge, bound, obligation, identity, lane, coverage
):
    if lane["engine"] != "codeql":
        return True
    from .deep_audit_io import verify_codeql_query_selection

    try:
        evidence = challenge.get("codeql_query_inventory")
        baseline = coverage.get("codeql_query_inventory")
        if not _codeql_query_inventory_artifact_matches(
            execution, evidence, baseline, lane
        ):
            return False
        verify_codeql_query_selection(
            evidence,
            baseline=baseline,
            disabled_rule_id=(
                obligation["detector_rule_id"] if identity[1] == "mutation" else None
            ),
        )
        return evidence.get("suite_sha256") == execution.get("effective_config_sha256")
    except (RuntimeAuditError, ValueError, TypeError, KeyError, AttributeError):
        return False


def _codeql_query_inventory_artifact_matches(execution, evidence, baseline, lane):
    if not isinstance(evidence, dict) or evidence.get("schema") != (
        "factory.codeql-query-inventory.v1"
    ):
        return False
    if not isinstance(baseline, dict):
        return False
    artifacts = {item["kind"]: item for item in execution["native_artifacts"]}
    artifact = artifacts["query_inventory"]
    raw = canonical_bytes(evidence)
    return (
        lane.get("rule_ids") == sorted(baseline.get("query_ids", {}))
        and artifact["sha256"] == sha256_bytes(raw)
        and artifact["bytes"] == len(raw)
    )


def _trivy_challenge_artifacts_match(execution, evidence):
    import base64

    artifacts = {item["kind"]: item for item in execution["native_artifacts"]}
    roles = {"sarif": "sarif_report", "json": "policy_inventory"}
    for observation in evidence["observations"]:
        raw = base64.b64decode(observation["raw_report_base64"], validate=True)
        artifact = artifacts[roles[observation["format"]]]
        if artifact["sha256"] != sha256_bytes(raw) or artifact["bytes"] != len(raw):
            return False
    return True


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
        and _challenge_execution_config_valid_v2(
            execution, obligation, identity, lane, coverage
        )
    )


def _challenge_execution_config_valid_v2(
    execution, obligation, identity, lane, coverage=None
):
    baseline = _challenge_baseline_config_sha256(lane, coverage)
    if baseline is None:
        return False
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
        expected_effective = baseline
    return (
        execution.get("effective_config_sha256") == expected_effective
        and execution.get("baseline_config_sha256") == baseline
        and execution.get("mutation") == expected_mutation
    )


def _challenge_baseline_config_sha256(lane, coverage=None):
    if lane["engine"] == "osv":
        return _osv_baseline_config_sha256(lane)
    if lane["engine"] == "codeql":
        inventory = (coverage or {}).get("codeql_query_inventory")
        if not isinstance(inventory, dict):
            return None
        try:
            require_digest(inventory.get("suite_sha256"), "CodeQL suite hash")
        except RuntimeAuditError:
            return None
        return inventory["suite_sha256"]
    if lane["engine"] != "trivy":
        return lane["ruleset_sha256"]
    policy = lane.get("native_policy")
    if not isinstance(policy, dict) or set(policy) != {
        "config_sha256",
        "baseline_ignore_sha256",
    }:
        return None
    try:
        for value in policy.values():
            require_digest(value, "native policy digest")
    except RuntimeAuditError:
        return None
    return policy["baseline_ignore_sha256"]


def _osv_baseline_config_sha256(lane):
    policy = lane.get("native_policy")
    if not isinstance(policy, dict):
        return None
    try:
        return require_digest(policy.get("baseline_config_sha256"), "OSV baseline")
    except RuntimeAuditError:
        return None


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
    dependency_accounting = (
        _osv_source_accounting(report, required, lane["mode"])
        if lane["engine"] == "osv" and lane["mode"] == "offline-pypi-snapshot"
        else None
    )
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
    gaps.extend(
        _osv_retained_evidence_gaps(
            coverage, lane, required, report, challenges, obligations
        )
    )
    gaps.extend(_fuzz_retained_evidence_gaps(report, lane, sources))
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
        "covered_paths": (
            dependency_accounting["measured_paths"]
            if dependency_accounting is not None
            else sorted(required)
        ),
        **(
            {"source_accounting": dependency_accounting}
            if dependency_accounting is not None
            else {}
        ),
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


def _usable_native_fingerprint(analyzer: dict, native: dict) -> bool:
    semgrep = analyzer["driver"].lower() in {"semgrep", "semgrep oss"}
    return any(
        value.strip()
        and not (
            semgrep
            and name == "fingerprints:matchBasedId/v1"
            and value.strip().lower() == "requires login"
        )
        for name, value in native.items()
    )


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
    if not _usable_native_fingerprint(analyzer, native):
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


def _native_sarif_metadata(report: dict, profile: dict, invocations: list) -> dict:
    """Supplement absent metadata from measured execution; preserve native bytes hash."""
    import copy

    report = copy.deepcopy(report)
    runs = report.get("runs")
    if not isinstance(runs, list) or not 1 <= len(runs) <= 16:
        raise _deep_audit_io.RuntimeAuditError(
            "E_REPORT_JSON", "native SARIF runs missing"
        )
    for run in runs:
        driver = run["tool"]["driver"]
        if driver.get("version", profile["tool_version"]) != profile["tool_version"]:
            raise _deep_audit_io.RuntimeAuditError(
                "E_TOOLCHAIN_DRIFT", "native report version differs"
            )
        driver.setdefault("version", profile["tool_version"])
        run.setdefault(
            "invocations",
            [
                {
                    "executionSuccessful": True,
                    "properties": {
                        "factory_execution_sha256": _deep_audit_io.digest(invocations)
                    },
                }
            ],
        )
    return report


def _native_junit(
    output: _deep_audit_io.Path, sources: dict, junit_name: str = "runtime.xml"
) -> tuple:
    return _deep_audit_io._parse_runtime_junit(
        _deep_audit_io._junit_bytes(output, junit_name), sources
    )


def _parse_runtime_junit(junit: bytes, sources: dict) -> tuple:
    import xml.etree.ElementTree as ET

    if (
        len(junit) > _deep_audit_io.LIMIT
        or b"<!DOCTYPE" in junit.upper()
        or b"<!ENTITY" in junit.upper()
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_REPORT", "unsafe or oversized JUnit"
        )
    try:
        tree = ET.fromstring(junit)
    except ET.ParseError as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_REPORT", "invalid native JUnit"
        ) from exc
    cases = list(tree.iter("testcase"))
    _deep_audit_io._junit_suite_counts(tree, cases)
    return _deep_audit_io._junit_observations(
        cases, sources, _deep_audit_io.sha256_bytes(junit)
    )


def _junit_suite_counts(tree, cases):
    suites = [tree] if tree.tag == "testsuite" else list(tree.iter("testsuite"))
    if not suites or not cases:
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_REPORT", "no executed source-bound tests"
        )
    try:
        declared = sum(int(suite.attrib["tests"]) for suite in suites)
        declared_failures = sum(int(suite.get("failures", "0")) for suite in suites)
        declared_errors = sum(int(suite.get("errors", "0")) for suite in suites)
    except (KeyError, ValueError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_REPORT", "JUnit suite counts malformed"
        ) from exc
    actual_failures = sum(case.find("failure") is not None for case in cases)
    actual_errors = sum(case.find("error") is not None for case in cases)
    if (
        declared != len(cases)
        or declared_failures != actual_failures
        or declared_errors != actual_errors
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_REPORT", "JUnit suite counts differ"
        )


def _junit_observations(cases, sources, junit_hash):
    findings, identities, executed = [], set(), []
    for case in cases:
        result = _deep_audit_io._junit_case(case, sources)
        path, finding, skipped = result
        identity = (path, case.get("classname", ""), case.get("name", ""))
        if identity in identities:
            raise _deep_audit_io.RuntimeAuditError(
                "E_RUNTIME_REPORT", "duplicate JUnit testcase"
            )
        identities.add(identity)
        if not skipped:
            executed.append(path)
        if finding is not None:
            findings.append(finding)
    if not executed:
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_REPORT", "no executed source-bound tests"
        )
    harness_path = min(executed)
    findings.sort(key=lambda item: (item["path"], item["line"], item["rule_id"]))
    return (
        len(executed),
        findings,
        {
            "path": harness_path,
            "sha256": sources[harness_path],
        },
        junit_hash,
    )


def _junit_bytes(output, junit_name="runtime.xml"):
    with _deep_audit_io.local_file(output, junit_name).open("rb") as stream:
        junit = stream.read(_deep_audit_io.LIMIT + 1)
    if (
        len(junit) > _deep_audit_io.LIMIT
        or b"<!DOCTYPE" in junit.upper()
        or b"<!ENTITY" in junit.upper()
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_REPORT", "unsafe or oversized JUnit"
        )
    return junit


def _junit_case(case, sources):
    raw_path = case.get("file", "")
    if raw_path.startswith("/src/"):
        raw_path = raw_path.removeprefix("/src/")
    path = _deep_audit_io.relative_path(raw_path)
    if path not in sources:
        raise _deep_audit_io.RuntimeAuditError(
            "E_HARNESS_BINDING", "JUnit test source is unbound"
        )
    if case.find("skipped") is not None:
        return path, None, True
    finding = None
    if case.find("failure") is not None or case.find("error") is not None:
        try:
            line = int(case.get("line", "0")) + 1
        except ValueError as exc:
            raise _deep_audit_io.RuntimeAuditError(
                "E_RUNTIME_REPORT", "invalid JUnit failure line"
            ) from exc
        finding = {
            "rule_id": "RUNTIME_TEST_FAILURE",
            "path": path,
            "line": line,
            "severity": "high",
        }
    return path, finding, False


def _native_coverage_report(
    raw: dict,
    lane: dict,
    inventory: dict,
    output: _deep_audit_io.Path,
    junit_name="runtime.xml",
) -> dict:
    if raw.get("meta", {}).get("branch_coverage") is not True:
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "native branch measurement required"
        )
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    tests, findings, harness, junit_hash = _deep_audit_io._native_junit(
        output, sources, junit_name
    )
    coverage = _deep_audit_io._native_source_counts(raw, sources)
    return {
        "schema": "factory.deep-runtime-observations.v1",
        "engine": "runtime",
        "tool_version": lane["tool_version"],
        "completed": True,
        "errors": [],
        "harness": harness,
        "metrics": {"tests": tests},
        "findings": findings,
        "source_coverage": coverage,
        "coverage_native_sha256": _deep_audit_io.digest(raw),
        "junit_sha256": junit_hash,
    }


def _native_source_counts(raw: dict, sources: dict) -> dict:
    coverage = {}
    files = raw.get("files")
    if not isinstance(files, dict) or not all(isinstance(name, str) for name in files):
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "native coverage files object required"
        )
    for name, measured in files.items():
        path = _deep_audit_io.relative_path(name.removeprefix("/src/"))
        if path not in sources:
            raise _deep_audit_io.RuntimeAuditError(
                "E_RUNTIME_COVERAGE", "coverage source is unbound"
            )
        if path in coverage:
            raise _deep_audit_io.RuntimeAuditError(
                "E_RUNTIME_COVERAGE", "duplicate native coverage source"
            )
        counts = _deep_audit_io._native_coverage_counts(measured)
        coverage[path] = {
            "sha256": sources[path],
            "lines_total": counts["num_statements"],
            "lines_covered": counts["covered_lines"],
            "branches_total": counts["num_branches"],
            "branches_covered": counts["covered_branches"],
        }
    return coverage


def _native_coverage_counts(measured: dict) -> dict:
    """Validate measured totals before exposing them as runtime facts."""
    if not isinstance(measured, dict) or not isinstance(measured.get("summary"), dict):
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "native coverage summary required"
        )
    counts = measured["summary"]
    for field in (
        "num_statements",
        "covered_lines",
        "num_branches",
        "covered_branches",
    ):
        _deep_audit_io.require_int(
            counts.get(field), field, minimum=0, maximum=10_000_000
        )
    if (
        counts["covered_lines"] > counts["num_statements"]
        or counts["covered_branches"] > counts["num_branches"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "covered counts exceed measured totals"
        )
    return counts


def _native_report(
    raw: dict,
    profile: dict,
    contract: dict,
    output: _deep_audit_io.Path,
    invocations: list,
) -> dict:
    import copy

    sources = {item["path"]: item["sha256"] for item in contract["inventory"]["files"]}
    if profile["report_format"] == "sarif":
        report = _deep_audit_io._native_sarif_metadata(raw, profile, invocations)
        return _deep_audit_io._native_sarif_paths(report, sources)
    if profile["report_format"] == "runtime-junit":
        report = _deep_audit_io._runtime_report_file(
            raw, contract["lane"], contract["inventory"], output
        )
        _deep_audit_io._runtime_exit_consistency(report, invocations)
        return report
    if profile["report_format"] == "coverage-json":
        return _deep_audit_io._native_coverage_report(
            raw,
            contract["lane"],
            contract["inventory"],
            output,
        )
    if profile["engine"] == "atheris":
        report = _deep_audit_io._finalize_fuzz_report(raw, invocations)
        corpus_path = output / _deep_audit_io.Path(
            contract["lane"]["report"]
        ).with_suffix(".corpus.json")
        with _deep_audit_io.local_file(
            output, corpus_path.relative_to(output).as_posix()
        ).open("rb") as stream:
            corpus_raw = stream.read(4_194_305)
        if len(corpus_raw) > 4_194_304:
            raise _deep_audit_io.RuntimeAuditError(
                "E_FUZZ_CORPUS", "corpus artifact budget exceeded"
            )
        _deep_audit_io._validate_fuzz_corpus(corpus_raw, report, sources)
        report["fuzz_corpus"] = _deep_audit_io._codeql_native_blob(
            corpus_raw, maximum=4_194_304
        )
        return report
    report = copy.deepcopy(raw)
    _deep_audit_io._native_dependency_paths(report, profile["report_format"], sources)
    return report


def _native_source_path(uri: str, sources: dict, *, scan_root: bool = False) -> str:
    _deep_audit_io.require_str(uri, "native source URI", maximum=2048)
    path = uri.removeprefix("file:///src/").removeprefix("/src/")
    if scan_root and path.startswith("/"):
        path = path[1:]  # Native Syft directory locations start at the scan root.
    path = _deep_audit_io.relative_path(path)
    if path not in sources:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRACE_UNBOUND", "native source is outside candidate"
        )
    return path


def _native_artifact_path(artifact: dict, run: dict, sources: dict) -> str:
    uri, indexed_uri = _deep_audit_io._native_artifact_uri(artifact, run)
    path = _deep_audit_io._native_source_path(uri, sources)
    if (
        indexed_uri is not None
        and _deep_audit_io._native_source_path(indexed_uri, sources) != path
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SARIF_INDIRECTION", "native artifact reference differs"
        )
    return path


def _native_artifact_uri(artifact, run):
    indexed_uri = None
    if "index" in artifact:
        indexed_uri = _deep_audit_io._indexed_artifact_uri(artifact, run)
        if not isinstance(indexed_uri, dict):
            raise _deep_audit_io.RuntimeAuditError(
                "E_SARIF_INDIRECTION", "indexed artifact is invalid"
            )
    value = artifact if "uri" in artifact else indexed_uri
    if not isinstance(value, dict):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SARIF_INDIRECTION", "native source URI missing"
        )
    uri = _deep_audit_io.require_str(
        value.get("uri"), "native source URI", maximum=2048
    )
    absolute_source = uri.startswith(("/src/", "file:///src/"))
    if "uriBaseId" in value and not absolute_source:
        base = run.get("originalUriBaseIds", {}).get(value["uriBaseId"], {})
        if base.get("uri") not in {"file:///src/", "file:///src", "/src/"}:
            raise _deep_audit_io.RuntimeAuditError(
                "E_SARIF_INDIRECTION", "untrusted native source base"
            )
    return uri, indexed_uri.get("uri") if indexed_uri is not None else None


def _indexed_artifact_uri(artifact, run):
    index = _deep_audit_io.require_int(
        artifact["index"], "artifact index", minimum=0, maximum=49999
    )
    items = run.get("artifacts", [])
    if index >= len(items):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SARIF_INDIRECTION", "artifact index is absent"
        )
    return items[index]["location"]


def _native_sarif_paths(report: dict, sources: dict) -> dict:
    for run in report["runs"]:
        stack = [run]
        count = 0
        while stack:
            item = stack.pop()
            count += 1
            if count > 200000:
                raise _deep_audit_io.RuntimeAuditError(
                    "E_REPORT_SIZE", "native SARIF tree exceeds budget"
                )
            if isinstance(item, list):
                stack.extend(item)
            elif isinstance(item, dict):
                if "artifactLocation" in item:
                    artifact = item["artifactLocation"]
                    path = _deep_audit_io._native_artifact_path(artifact, run, sources)
                    artifact.update(uri=path)
                    artifact.pop("uriBaseId", None)
                    artifact.pop("index", None)
                stack.extend(item.values())
    return report


def _native_dependency_paths(report: dict, kind: str, sources: dict) -> None:
    if kind == "osv-json":
        for result in report.get("results", []):
            result["source"]["path"] = _deep_audit_io._native_source_path(
                result["source"]["path"], sources
            )
        _deep_audit_io._osv_lookup_paths(
            report, lambda path: _deep_audit_io._native_source_path(path, sources)
        )
    elif kind == "syft-json":
        for artifact in report.get("artifacts", []):
            for location in artifact.get("locations", []):
                location["path"] = _deep_audit_io._native_source_path(
                    location["path"], sources, scan_root=True
                )


def _osv_lookup_paths(report, normalize):
    if "factory_lookup_execution" not in report:
        return
    ledger = report["factory_lookup_execution"]
    if not isinstance(ledger, dict) or not isinstance(ledger.get("queries"), list):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_LOOKUPS", "native lookup object required"
        )
    if len(ledger["queries"]) > 20_000:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_LOOKUPS", "native query budget exceeded"
        )
    for row in ledger["queries"]:
        if not isinstance(row, dict) or not isinstance(row.get("locations"), list):
            raise _deep_audit_io.RuntimeAuditError(
                "E_OSV_LOOKUPS", "native query locations required"
            )
        if not 0 < len(row["locations"]) <= 20_000:
            raise _deep_audit_io.RuntimeAuditError(
                "E_OSV_LOOKUPS", "native location budget exceeded"
            )
        row["locations"] = sorted(normalize(path) for path in row["locations"])


def _osv_suppression_bytes(aliases):
    if (
        not isinstance(aliases, list)
        or not 1 <= len(aliases) <= 64
        or any(
            not isinstance(item, str)
            or _deep_audit_io.re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", item)
            is None
            for item in aliases
        )
        or aliases != sorted(set(aliases))
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_POLICY", "canonical advisory aliases required"
        )
    return "".join(
        "[[IgnoredVulns]]\nid = "
        + _deep_audit_io.json.dumps(item, ensure_ascii=True)
        + "\n\n"
        for item in aliases
    ).encode("ascii")


def _osv_challenge_source_paths(report, source_root, manifest):
    results = report.get("results")
    if not isinstance(results, list):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_REPORT", "native source results required"
        )
    prefix = source_root.resolve().as_posix().rstrip("/") + "/"
    for result in results:
        try:
            source = result["source"]
            raw_path = _deep_audit_io.require_str(
                source.get("path"), "OSV source path", maximum=2048
            )
            if raw_path.startswith("file://"):
                raw_path = raw_path.removeprefix("file://")
            if raw_path.startswith(prefix):
                path = raw_path[len(prefix) :]
            elif raw_path in manifest:
                path = raw_path
            else:
                raise _deep_audit_io.RuntimeAuditError(
                    "E_OSV_REPORT", "source path outside fixture"
                )
            path = _deep_audit_io.relative_path(path)
            if path not in manifest:
                raise _deep_audit_io.RuntimeAuditError(
                    "E_OSV_REPORT", "source path is unbound"
                )
            source["path"] = path
        except (KeyError, TypeError, AttributeError) as exc:
            raise _deep_audit_io.RuntimeAuditError(
                "E_OSV_REPORT", "native source path malformed"
            ) from exc
    _deep_audit_io._osv_lookup_paths(
        report,
        lambda path: _deep_audit_io._osv_normalize_lookup_path(path, prefix, manifest),
    )


def _osv_normalize_lookup_path(path, prefix, manifest):
    path = _deep_audit_io.require_str(path, "lookup source path", maximum=2048)
    path = path.removeprefix("file://")
    if path.startswith(prefix):
        path = path[len(prefix) :]
    path = _deep_audit_io.relative_path(path)
    if path not in manifest:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_LOOKUPS", "lookup source path is unbound"
        )
    return path


def _osv_normalize_result_source(item, root, manifest):
    try:
        source = item["source"]
        raw = _deep_audit_io.require_str(
            source.get("path"), "source path", maximum=2048
        )
        if raw.startswith("file://"):
            raw = raw[7:]
        path = raw[len(root) :] if raw.startswith(root) else raw
        path = _deep_audit_io.relative_path(path)
        if path not in manifest:
            raise ValueError("unbound source path")
        source["path"] = path
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_ARTIFACT", "unbound OSV source path"
        ) from exc


def _native_profile_report(profile, output, paths):
    if profile["report_format"] == "runtime-junit":
        junit_path = _deep_audit_io.local_file(output, paths[0])
        _deep_audit_io._junit_bytes(output, paths[0])
        with _deep_audit_io.local_file(output, paths[1]).open("rb") as stream:
            raw_report = _deep_audit_io.strict_json(
                stream.read(_deep_audit_io.LIMIT + 1)
            )
        if not junit_path.is_file():
            raise _deep_audit_io.RuntimeAuditError(
                "E_RUNTIME_REPORT", "native JUnit missing"
            )
    else:
        with _deep_audit_io.local_file(output, paths[0]).open("rb") as stream:
            raw_report_bytes = stream.read(_deep_audit_io.LIMIT + 1)
        if len(raw_report_bytes) > _deep_audit_io.LIMIT:
            raise _deep_audit_io.RuntimeAuditError(
                "E_REPORT_SIZE", "native report exceeds budget"
            )
        raw_report = _deep_audit_io.strict_json(raw_report_bytes)
    return raw_report, (
        raw_report_bytes if profile["report_format"] != "runtime-junit" else None
    )


def _trivy_full_source_execution(
    profile,
    lane,
    inventory,
    source,
    output,
    paths,
    sarif_argv,
    invocation,
    config,
    ignore,
    started,
    timeout,
    scratch,
):
    import base64
    from .runtime_audit_process import run_bounded_command

    remaining = int(timeout - (_deep_audit_io.time.monotonic() - started))
    if remaining < 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "Trivy inventory budget exhausted"
        )
    raw_sarif = _deep_audit_io._trivy_read_raw(
        _deep_audit_io.local_file(output, paths[0])
    )
    json_path = scratch / "trivy-full.json"
    json_run = scratch / "trivy-full-run"
    json_run.mkdir()
    argv = _deep_audit_io._trivy_json_argv(sarif_argv, json_path)
    deadline = _deep_audit_io.time.monotonic() + remaining
    facts = run_bounded_command(argv, source, remaining, json_run)
    if _deep_audit_io._adapter_command_failed(facts, [0], deadline):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy JSON inventory failed"
        )
    raw_json = _deep_audit_io._trivy_read_raw(
        _deep_audit_io.local_file(scratch, "trivy-full.json")
    )
    sources = _deep_audit_io._trivy_source_map(inventory, lane)
    native_report = _deep_audit_io.strict_json(raw_json)
    source_bytes = _deep_audit_io._trivy_source_bytes(source, sources)
    bindings = _deep_audit_io._trivy_target_bindings(
        native_report, sources, source_bytes
    )
    _deep_audit_io._trivy_native_checks(native_report, sources, bindings)
    return {
        "schema": "factory.trivy-rule-execution.v1",
        "config_base64": base64.b64encode(config).decode("ascii"),
        "ignore_base64": base64.b64encode(ignore).decode("ascii"),
        "sources": _deep_audit_io._trivy_source_map(inventory, lane),
        "target_bindings": bindings,
        "source_bytes_base64": {
            path: base64.b64encode(raw).decode("ascii")
            for path, raw in sorted(source_bytes.items())
        },
        "observations": [
            _deep_audit_io._trivy_observation(
                "sarif", sarif_argv, invocation["execution"], raw_sarif
            ),
            _deep_audit_io._trivy_observation("json", argv, facts, raw_json),
        ],
    }


def _trivy_read_raw(path):
    raw = path.read_bytes()
    if len(raw) > _deep_audit_io.LIMIT:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_REPORT", "Trivy report exceeds byte budget"
        )
    return raw


def _trivy_observation(report_format, argv, facts, raw):
    import base64

    return {
        "format": report_format,
        "argv": argv,
        "execution": facts,
        "raw_report_base64": base64.b64encode(raw).decode("ascii"),
        "raw_report_sha256": _deep_audit_io.sha256_bytes(raw),
    }


def _trivy_source_map(inventory, lane):
    return {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }


def _trivy_source_bytes(root, sources):
    result = {}
    total = 0
    for path, expected in sorted(sources.items()):
        raw = (root / path).read_bytes()
        total += len(raw)
        if (
            len(raw) > 1_000_000
            or total > 8_000_000
            or _deep_audit_io.sha256_bytes(raw) != expected
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_APPLICABILITY", "Terraform source snapshot differs"
            )
        result[path] = raw
    return result


def _trivy_module_sources(raw, path):
    import re
    import json

    text = raw.decode("utf-8", errors="strict")
    if path.lower().endswith(".tf.json"):
        try:
            document = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_APPLICABILITY", "Terraform JSON source is malformed"
            ) from exc
        modules = document.get("module", {}) if isinstance(document, dict) else None
        if modules is None:
            return []
        if not isinstance(modules, dict):
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_APPLICABILITY", "Terraform JSON modules are malformed"
            )
        sources = []
        for module in modules.values():
            source = module.get("source") if isinstance(module, dict) else None
            if not isinstance(source, str) or "$" in source:
                raise _deep_audit_io.RuntimeAuditError(
                    "E_TRIVY_APPLICABILITY",
                    "Terraform JSON module source is dynamic or missing",
                )
            sources.append((path, source))
        return sources
    text = _deep_audit_io._trivy_clean_hcl_comments(text)
    return [
        (path, source) for source in _deep_audit_io._trivy_parse_module_blocks(text, re)
    ]


def _trivy_clean_hcl_comments(text):
    lines = []
    for line in text.splitlines():
        out = []
        quoted = False
        escaped = False
        index = 0
        while index < len(line):
            char = line[index]
            pair = line[index : index + 2]
            if not quoted and pair in {"/*", "*/", "<<"}:
                raise _deep_audit_io.RuntimeAuditError(
                    "E_TRIVY_APPLICABILITY",
                    "Terraform block comments and heredocs are unsupported",
                )
            if quoted:
                out.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
                out.append(char)
            elif char == "#" or pair == "//":
                break
            else:
                out.append(char)
            index += 2 if not quoted and pair == "//" else 1
        lines.append("".join(out))
    return "\n".join(lines)


def _trivy_parse_module_blocks(text, regex):
    lines = text.splitlines()
    modules = []
    index = 0
    while index < len(lines):
        if not regex.match(r'^\s*module\s+"[^"\n]+"\s*\{', lines[index]):
            index += 1
            continue
        block, index = _deep_audit_io._trivy_hcl_block(lines, index)
        match = regex.search(r'^\s*source\s*=\s*"([^"$]+)"\s*$', block, regex.MULTILINE)
        if match is None:
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_APPLICABILITY", "Terraform module source is dynamic or missing"
            )
        modules.append(match.group(1))
    return modules


def _trivy_hcl_block(lines, start):
    depth = 0
    in_string = False
    escaped = False
    block = []
    cursor = start
    while cursor < len(lines):
        line = lines[cursor]
        block.append(line)
        depth, in_string, escaped = _deep_audit_io._trivy_hcl_line_depth(
            line, depth, in_string, escaped
        )
        if depth == 0:
            return "\n".join(block), cursor + 1
        cursor += 1
    raise _deep_audit_io.RuntimeAuditError(
        "E_TRIVY_APPLICABILITY", "Terraform module block is unclosed"
    )


def _trivy_hcl_line_depth(line, depth, in_string, escaped):
    comment = False
    for char in line:
        if comment:
            break
        depth, in_string, escaped, comment = _deep_audit_io._trivy_hcl_char(
            char, depth, in_string, escaped
        )
    return depth, in_string, escaped


def _trivy_hcl_char(char, depth, in_string, escaped):
    if in_string:
        return _deep_audit_io._trivy_hcl_string_char(char, depth, escaped)
    if char == '"':
        return depth, True, False, False
    if char == "#":
        return depth, False, False, True
    return depth + (char == "{") - (char == "}"), False, False, False


def _trivy_hcl_string_char(char, depth, escaped):
    if escaped:
        return depth, True, False, False
    if char == "\\":
        return depth, True, True, False
    return depth, char != '"', False, False


def _trivy_target_bindings(report, sources, source_bytes=None):
    """Bind native Terraform Targets to exact candidate members and hashes."""
    results = report.get("Results") if isinstance(report, dict) else None
    if not isinstance(results, list):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_REPORT", "Trivy target inventory malformed"
        )
    paths = set(sources)
    root_members, root_edges, root_prefixes = _deep_audit_io._trivy_root_module_graphs(
        results, paths, source_bytes
    )
    bindings = _deep_audit_io._trivy_bind_report_targets(
        results, paths, sources, root_members, root_edges, source_bytes, root_prefixes
    )
    _deep_audit_io._trivy_validate_target_coverage(bindings, paths)
    return bindings


def _trivy_root_module_graphs(results, paths, source_bytes):
    members_by_target, edges_by_target, prefixes = {}, {}, {}
    if source_bytes is None:
        return members_by_target, edges_by_target, prefixes
    for result in results:
        if not isinstance(result, dict) or result.get("Type") != "terraform":
            continue
        target = _deep_audit_io._trivy_target_name(result.get("Target"))
        prefix = _deep_audit_io._trivy_root_target_prefix(target, paths)
        if prefix is None:
            continue
        members, edges = _deep_audit_io._trivy_root_module_graph(
            paths, source_bytes, True, prefix
        )
        if not members:
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_APPLICABILITY", "Terraform root target has no source members"
            )
        members_by_target[target] = members
        edges_by_target[target] = edges
        prefixes[target] = prefix
    return members_by_target, edges_by_target, prefixes


def _trivy_root_target_prefix(target, paths):
    if target == ".":
        # A dot target is the scan root. Candidate paths are already relative
        # to that root; never infer a hidden root from a shared path prefix.
        return ""
    if target.lower().endswith((".tf", ".tf.json")):
        return None
    direct_members = [
        path
        for path in paths
        if _deep_audit_io.Path(path).parent.as_posix() == target
        and path.lower().endswith((".tf", ".tf.json"))
    ]
    return target if direct_members else None


def _trivy_root_module_graph(paths, source_bytes, root_scan, root_prefix=""):
    root_members = set()
    edges = []
    if source_bytes is None or not root_scan:
        return root_members, edges
    root_directory = root_prefix or "."
    pending = [
        path
        for path in paths
        if _deep_audit_io.Path(path).parent.as_posix() == root_directory
        and path.lower().endswith((".tf", ".tf.json"))
    ]
    while pending:
        parent = pending.pop()
        if parent in root_members:
            continue
        root_members.add(parent)
        for owner, source in _deep_audit_io._trivy_module_sources(
            source_bytes[parent], parent
        ):
            members = _deep_audit_io._trivy_local_module_members(owner, source, paths)
            edges.append({"from": owner, "source": source, "members": members})
            pending.extend(members)
    return root_members, edges


def _trivy_local_module_members(owner, source, paths):
    if not source.startswith("./"):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_APPLICABILITY", "non-local Terraform module source is unsupported"
        )
    resolved = _deep_audit_io.Path(
        _deep_audit_io.os.path.normpath(str(_deep_audit_io.Path(owner).parent / source))
    ).as_posix()
    if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_APPLICABILITY", "Terraform module source escapes candidate root"
        )
    members = sorted(
        path
        for path in paths
        if _deep_audit_io.Path(path).parent.as_posix() == resolved
        and path.lower().endswith((".tf", ".tf.json"))
    )
    if not members:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_APPLICABILITY", "Terraform local module has no inventoried sources"
        )
    return members


def _trivy_bind_report_targets(
    results,
    paths,
    sources,
    root_members,
    root_edges,
    source_bytes,
    root_prefixes,
):
    bindings = {}
    for result in results:
        if not isinstance(result, dict):
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_REPORT", "Trivy target malformed"
            )
        target = _deep_audit_io._trivy_target_name(result.get("Target"))
        kind = result.get("Type")
        if target in bindings:
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_REPORT", "duplicate Trivy target"
            )
        members, scope = _deep_audit_io._trivy_target_members(
            target, kind, paths, root_members, source_bytes, root_prefixes
        )
        if not members:
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_APPLICABILITY", "Trivy target has no bound members"
            )
        bindings[target] = {
            "kind": kind,
            "scope": scope,
            "members": [{"path": path, "sha256": sources[path]} for path in members],
        }
    if source_bytes is not None:
        for target, item in bindings.items():
            if item["scope"] == "terraform_root":
                item["module_edges"] = sorted(
                    root_edges[target], key=lambda edge: (edge["from"], edge["source"])
                )
    return bindings


def _trivy_target_members(
    target, kind, paths, root_members, source_bytes, root_prefixes
):
    if kind != "terraform":
        return ([target] if target in paths else []), "file"
    if target in root_members:
        members = sorted(root_members[target])
        return members, "terraform_root"
    if target == "." and source_bytes is None:
        members = sorted(
            path
            for path in paths
            if "/" not in path and path.lower().endswith((".tf", ".tf.json"))
        )
        return members, "terraform_root"
    if target.lower().endswith((".tf", ".tf.json")):
        return _deep_audit_io._trivy_terraform_file_target_members(
            target, paths, root_members, root_prefixes
        )
    return ([target] if target in paths else []), "file"


def _trivy_terraform_file_target_members(target, paths, root_members, root_prefixes):
    prefixes = [
        root_prefixes.get(root_target, "")
        for root_target in root_members
        if root_target == "." or target.startswith(root_target + "/")
    ]
    candidates = {target}
    candidates.update(f"{prefix}/{target}" for prefix in prefixes if prefix)
    found = sorted(candidates & paths)
    if len(found) > 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_APPLICABILITY", "Terraform file target mapping is ambiguous"
        )
    return found, "terraform_file"


def _trivy_validate_target_coverage(bindings, paths):
    covered = {row["path"] for item in bindings.values() for row in item["members"]}
    if covered != paths:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_APPLICABILITY", "Trivy target membership is incomplete"
        )
    for path in paths:
        owners = [
            item
            for item in bindings.values()
            if any(row["path"] == path for row in item["members"])
        ]
        if len(owners) > 1 and not (
            len(owners) == 2
            and "terraform_root" in {item["scope"] for item in owners}
            and all(
                item["scope"] in {"terraform_root", "terraform_file"} for item in owners
            )
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_APPLICABILITY", "Trivy target membership overlaps"
            )


def _trivy_native_checks(report, sources, target_bindings=None):
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_REPORT", "Trivy JSON schema version differs"
        )
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_APPLICABILITY", "Trivy reported no applicable sources"
        )
    target_bindings = target_bindings or _deep_audit_io._trivy_target_bindings(
        report, sources
    )
    matrix = {}
    for result in results:
        if not isinstance(result, dict) or result.get("Class") != "config":
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_REPORT", "Trivy config result malformed"
            )
        target = _deep_audit_io._trivy_target_name(result.get("Target"))
        if target not in target_bindings:
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_APPLICABILITY", "Trivy source is unbound"
            )
        rows = result.get("Misconfigurations")
        if not isinstance(rows, list) or not rows:
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_APPLICABILITY", "Trivy check inventory missing"
            )
        statuses = _deep_audit_io._trivy_check_statuses(result, rows)
        if target in matrix:
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_REPORT", "duplicate Trivy source result"
            )
        matrix[target] = statuses
    if set(matrix) != set(target_bindings):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_APPLICABILITY", "Trivy omitted a required target"
        )
    return matrix


def _trivy_check_statuses(result, rows):
    statuses = {}
    for row in rows:
        if not isinstance(row, dict):
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_REPORT", "Trivy check row malformed"
            )
        rule_id = _deep_audit_io.require_str(
            row.get("ID"), "Trivy check ID", maximum=256
        )
        status = row.get("Status")
        if (
            not isinstance(status, str)
            or status not in {"PASS", "FAIL"}
            or rule_id in statuses
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_REPORT", "Trivy check status is unsupported"
            )
        statuses[rule_id] = status
    summary = result.get("MisconfSummary")
    if (
        not isinstance(summary, dict)
        or type(summary.get("Successes")) is not int
        or type(summary.get("Failures")) is not int
        or summary.get("Successes")
        != sum(status == "PASS" for status in statuses.values())
        or summary.get("Failures")
        != sum(status == "FAIL" for status in statuses.values())
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_REPORT", "Trivy status summary differs"
        )
    return statuses


def _trivy_target_name(value):
    return "." if value == "." else _deep_audit_io.relative_path(value)


def _trivy_decode_source_bytes(evidence, sources):
    import base64

    encoded = evidence.get("source_bytes_base64")
    if not isinstance(encoded, dict) or set(encoded) != set(sources):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_APPLICABILITY", "Terraform source snapshot set differs"
        )
    decoded = {}
    total = 0
    for path, value in encoded.items():
        try:
            raw = base64.b64decode(value, validate=True)
        except (ValueError, TypeError) as exc:
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_APPLICABILITY", "Terraform source snapshot malformed"
            ) from exc
        total += len(raw)
        if (
            len(raw) > 1_000_000
            or total > 8_000_000
            or _deep_audit_io.sha256_bytes(raw) != sources[path]
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_APPLICABILITY", "Terraform source snapshot hash differs"
            )
        decoded[path] = raw
    return decoded


def _trivy_expected_failures(native, bindings, sarif, sources, source_root=None):
    report = _deep_audit_io._trivy_normalized_sarif(sarif, sources, source_root)
    rows = _deep_audit_io._trivy_native_failure_rows(native, bindings)
    expected = _deep_audit_io._trivy_match_failure_rows(rows, report)
    actual = _deep_audit_io._trivy_sarif_failures(sarif, sources, source_root)
    if actual != expected:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "native JSON and SARIF findings differ"
        )
    return expected


def _trivy_normalized_sarif(sarif, sources, source_root):
    _deep_audit_io._trivy_sarif_failures(sarif, sources, source_root)
    report = _deep_audit_io.strict_json(_deep_audit_io.canonical_bytes(sarif))
    if source_root is not None:
        for run in report["runs"]:
            _deep_audit_io._normalize_challenge_run(run, source_root.rstrip("/"))
    return _deep_audit_io._native_sarif_paths(report, sources)


def _trivy_native_failure_rows(native, bindings):
    rows = []
    for result in native["Results"]:
        binding = bindings[_deep_audit_io._trivy_target_name(result["Target"])]
        rows.extend(
            (binding, row)
            for row in result["Misconfigurations"]
            if row["Status"] == "FAIL"
        )
    return rows


def _trivy_match_failure_rows(rows, report):
    expected = set()
    used = set()
    for binding, row in rows:
        candidates = []
        accepted_ids = {row.get("ID"), row.get("AVDID")}
        for run_index, run in enumerate(report["runs"]):
            for result_index, result in enumerate(run.get("results", [])):
                if result.get("ruleId") not in accepted_ids:
                    continue
                location = result["locations"][0]["physicalLocation"][
                    "artifactLocation"
                ]
                path = _deep_audit_io.relative_path(location.get("uri"))
                if path in {item["path"] for item in binding["members"]}:
                    key = (run_index, result_index)
                    if key not in used:
                        candidates.append((key, path, result["ruleId"]))
        if len(candidates) != 1:
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_EXECUTION", "failed Trivy target has ambiguous SARIF ownership"
            )
        key, path, rule = candidates[0]
        used.add(key)
        expected.add((path, rule))
    return expected


def _trivy_observation_bytes(item):
    import base64

    fields = {"format", "argv", "execution", "raw_report_base64", "raw_report_sha256"}
    if not isinstance(item, dict) or set(item) != fields:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy observation shape differs"
        )
    try:
        raw = base64.b64decode(item["raw_report_base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy report bytes are malformed"
        ) from exc
    if (
        len(raw) > _deep_audit_io.LIMIT
        or _deep_audit_io.sha256_bytes(raw) != item["raw_report_sha256"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy report bytes differ"
        )
    return raw


def _trivy_pair_identity(sarif_argv, json_argv):
    if not isinstance(sarif_argv, list) or not isinstance(json_argv, list):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy command vectors are missing"
        )
    _deep_audit_io._trivy_closed_argv(sarif_argv)
    expected = list(sarif_argv)
    try:
        expected[expected.index("--format") + 1] = "json"
        expected[expected.index("--output") + 1] = json_argv[
            json_argv.index("--output") + 1
        ]
        expected.insert(expected.index("config") + 1, "--include-non-failures")
    except (ValueError, IndexError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy command pair is malformed"
        ) from exc
    try:
        first_output = sarif_argv[sarif_argv.index("--output") + 1]
        second_output = json_argv[json_argv.index("--output") + 1]
        formats_match = (
            sarif_argv[sarif_argv.index("--format") + 1] == "sarif"
            and json_argv[json_argv.index("--format") + 1] == "json"
        )
        input_match = sarif_argv[-1] == json_argv[-1]
        fixed = (
            sarif_argv[0:2] == ["/usr/local/bin/trivy", "config"]
            and sarif_argv[sarif_argv.index("--config") + 1]
            == "/opt/factory/rules/trivy.yaml"
            and sarif_argv[sarif_argv.index("--ignorefile") + 1]
            == json_argv[json_argv.index("--ignorefile") + 1]
        )
    except (ValueError, IndexError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy command pair is incomplete"
        ) from exc
    if (
        json_argv != expected
        or first_output == second_output
        or not formats_match
        or not input_match
        or not fixed
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy command pair differs"
        )


def _trivy_closed_argv(argv):
    if len(argv) != 14:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy command is not closed"
        )
    expected = [
        "/usr/local/bin/trivy",
        "config",
        "--config",
        "/opt/factory/rules/trivy.yaml",
        "--skip-check-update",
        "--skip-version-check",
        "--disable-telemetry",
        "--ignorefile",
        argv[8],
        "--format",
        "sarif",
        "--output",
        argv[12],
        argv[13],
    ]
    if argv != expected or any(
        not value.startswith("/") for value in (argv[8], argv[12], argv[13])
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy command permits unbound options"
        )


def _trivy_sarif_failures(report, sources, source_root=None):
    import copy

    if not isinstance(report, dict) or not isinstance(report.get("runs"), list):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_REPORT", "Trivy SARIF is malformed"
        )
    normalized = copy.deepcopy(report)
    if source_root is not None:
        for run in normalized["runs"]:
            _deep_audit_io._normalize_challenge_run(run, source_root.rstrip("/"))
    normalized = _deep_audit_io._native_sarif_paths(normalized, sources)
    failures = set()
    for run in normalized["runs"]:
        for result in run.get("results", []):
            rule = _deep_audit_io.require_str(
                result.get("ruleId"), "Trivy SARIF rule ID", maximum=256
            )
            locations = result.get("locations", [])
            if len(locations) != 1:
                raise _deep_audit_io.RuntimeAuditError(
                    "E_TRIVY_REPORT", "Trivy finding location is ambiguous"
                )
            location = (
                locations[0].get("physicalLocation", {}).get("artifactLocation", {})
            )
            path = _deep_audit_io.relative_path(location.get("uri"))
            if path not in sources or (path, rule) in failures:
                raise _deep_audit_io.RuntimeAuditError(
                    "E_TRIVY_REPORT", "Trivy SARIF finding is unbound"
                )
            failures.add((path, rule))
    return failures


def _semgrep_json_findings(native, rule_id, sources):
    results = native.get("results")
    if not isinstance(results, list) or len(results) > 20_000:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "bounded native results required"
        )
    findings = []
    for result in results:
        if not isinstance(result, dict) or result.get("check_id") != rule_id:
            raise _deep_audit_io.RuntimeAuditError(
                "E_SEMGREP_EXECUTION", "unselected detector finding"
            )
        path = _deep_audit_io._native_source_path(result.get("path"), sources)
        line = _deep_audit_io.require_int(
            result.get("start", {}).get("line"),
            "finding line",
            minimum=1,
            maximum=10**9,
        )
        findings.append((rule_id, path, line))
    if len(set(findings)) != len(findings):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "duplicate native findings"
        )
    return findings


def _semgrep_sarif_findings(report, rule_ids, sources):
    findings = []
    for run in report["runs"]:
        for item in run.get("results", []):
            matches = [
                rule
                for rule in rule_ids
                if item["ruleId"] == rule or item["ruleId"].endswith("." + rule)
            ]
            if len(matches) != 1 or len(item["locations"]) != 1:
                raise _deep_audit_io.RuntimeAuditError(
                    "E_SEMGREP_EXECUTION", "baseline detector identity differs"
                )
            place = item["locations"][0]["physicalLocation"]
            path = _deep_audit_io._native_source_path(
                place["artifactLocation"]["uri"], sources
            )
            findings.append((matches[0], path, place["region"]["startLine"]))
    if len(set(findings)) != len(findings):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "duplicate baseline findings"
        )
    return findings


def _runtime_exit_consistency(report, invocations):
    if len(invocations) != 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_REPORT", "one runtime invocation required"
        )
    code = invocations[0].get("execution", {}).get("exit_code")
    expected = 1 if report["findings"] else 0
    if type(code) is not int or code != expected:
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_REPORT", "JUnit and process exit differ"
        )


def _runtime_report_file(raw, lane, inventory, output):
    if raw.get("meta", {}).get("branch_coverage") is not True:
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "native branch measurement required"
        )
    report_name = lane["report"]
    return _deep_audit_io._native_coverage_report(
        raw, lane, inventory, output, report_name
    )


def _codeql_result_path(query_path):
    try:
        parts = _deep_audit_io.relative_path(query_path).split("/")
    except (_deep_audit_io.RuntimeAuditError, TypeError, ValueError) as error:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_EXECUTION", "relative query path required"
        ) from error
    if (
        len(parts) < 4
        or parts[0] != "codeql"
        or parts[1] not in {"javascript-queries", "python-queries", "actions-queries"}
        or _deep_audit_io.re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", parts[2]) is None
        or not parts[-1].endswith(".ql")
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_EXECUTION", "pinned query path required"
        )
    return "results/" + "/".join(parts[:2] + parts[3:])[:-3] + ".bqrs"


def _codeql_result_sets(raw):
    if not isinstance(raw, bytes) or len(raw) > 65_536:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_EXECUTION", "bounded result info required"
        )
    try:
        sets = _deep_audit_io.json.loads(raw)["result-sets"]
        if not isinstance(sets, list) or not 1 <= len(sets) <= 64:
            raise ValueError("result sets required")
        result, names = [], set()
        for item in sets:
            name = _deep_audit_io.require_str(item["name"], "result name", maximum=256)
            rows = _deep_audit_io.require_int(
                item["rows"], "result rows", minimum=0, maximum=2**63 - 1
            )
            columns = item["columns"]
            if name in names or not isinstance(columns, list) or len(columns) > 256:
                raise ValueError("unique bounded result sets required")
            names.add(name)
            result.append({"name": name, "rows": rows, "columns": len(columns)})
        return result
    except (ValueError, KeyError, TypeError, _deep_audit_io.RuntimeAuditError) as error:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_EXECUTION", "invalid native result info"
        ) from error


def _codeql_parse_rows(raw):
    if not isinstance(raw, bytes) or len(raw) > _deep_audit_io.NATIVE_COVERAGE_LIMIT:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_SOURCE", "bounded source query output required"
        )
    try:
        result = _deep_audit_io.json.loads(raw)["#select"]
        if (
            not isinstance(result["columns"], list)
            or result["columns"]
            != [{"kind": "String"}, {"kind": "Integer"}, {"kind": "Integer"}]
            or not isinstance(result["tuples"], list)
        ):
            raise ValueError("three-column source rows required")
        if len(result["tuples"]) > 20_000:
            raise ValueError("source row budget exceeded")
        rows = {}
        for row in result["tuples"]:
            path, nodes, errors = row
            path = _deep_audit_io.relative_path(path)
            if path in rows:
                raise ValueError("duplicate source row")
            rows[path] = {
                "syntax_nodes": _deep_audit_io.require_int(
                    nodes, "syntax nodes", minimum=0, maximum=2**31 - 1
                ),
                "parse_errors": _deep_audit_io.require_int(
                    errors, "parse errors", minimum=0, maximum=2**31 - 1
                ),
            }
        return rows
    except (_deep_audit_io.RuntimeAuditError, ValueError, TypeError, KeyError) as error:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_SOURCE", "invalid native source query output"
        ) from error


def _codeql_source_query(profile):
    languages = {
        arg.removeprefix("--language=")
        for command in profile["commands"]
        for arg in command["argv"]
        if arg.startswith("--language=")
    }
    definitions = {
        "javascript-typescript": (
            "javascript",
            "TopLevel",
            "JSParseError",
            "e.getFile()",
            "",
        ),
        "python": ("python", "Module", "SyntaxError", "e.getFile()", ""),
        "actions": (
            "actions",
            "YamlDocument",
            "YamlParseError",
            "e.getLocation().getFile()",
            "import codeql.files.FileSystem\nimport codeql.actions.ast.internal.Yaml\n",
        ),
    }
    if len(languages) != 1 or not languages <= definitions.keys():
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_SOURCE", "one supported extractor required"
        )
    library, node, error, location, imports = definitions[languages.pop()]
    query = (
        f"import {library}\n{imports}from File f select f.getRelativePath(), "
        f"count({node} n | n.getFile()=f), count({error} e | {location}=f)\n"
    ).encode("utf-8")
    return library, query


def _trivy_paired_runner(runner, argv, cwd, budget, scratch, policy_path, paired):
    started = _deep_audit_io.time.monotonic()
    deadline = started + budget
    sarif_facts = runner(argv, cwd, budget, scratch)
    json_facts = None
    if not _deep_audit_io._adapter_command_failed(sarif_facts, [0], deadline):
        remaining = int(deadline - _deep_audit_io.time.monotonic())
        if remaining > 0:
            json_scratch = scratch / "json-run"
            json_scratch.mkdir()
            json_argv = _deep_audit_io._trivy_json_argv(argv, policy_path)
            json_facts = runner(json_argv, cwd, remaining, json_scratch)
            paired.update(json_argv=json_argv, json_facts=json_facts)
            if not _deep_audit_io._adapter_command_failed(json_facts, [0], deadline):
                paired["json_raw"] = _deep_audit_io.local_file(
                    scratch, "policy.json"
                ).read_bytes()
    paired.update(sarif_argv=argv, sarif_facts=sarif_facts)
    return _deep_audit_io._trivy_pair_facts(sarif_facts, json_facts, budget)


def _trivy_pair_facts(sarif, native, budget):
    facts = dict(sarif)
    other = native or {}
    facts.update(
        timeout_seconds=budget,
        duration_ms=min(
            3_600_000, sarif.get("duration_ms", 0) + other.get("duration_ms", 0)
        ),
        exit_code=(
            sarif.get("exit_code")
            if sarif.get("exit_code") != 0 or native is None
            else other.get("exit_code")
        ),
        timed_out=sarif.get("timed_out", False) or other.get("timed_out", False),
        launch_error=sarif.get("launch_error", False)
        or other.get("launch_error", False),
        output_limit_exceeded=sarif.get("output_limit_exceeded", False)
        or other.get("output_limit_exceeded", False),
        cleanup_confirmed=sarif.get("cleanup_confirmed", False)
        and (native is None or other.get("cleanup_confirmed", False)),
        stdout_sha256=_deep_audit_io.digest(
            [sarif.get("stdout_sha256"), other.get("stdout_sha256")]
        ),
        stderr_sha256=_deep_audit_io.digest(
            [sarif.get("stderr_sha256"), other.get("stderr_sha256")]
        ),
        stdout_bytes=sarif.get("stdout_bytes", 0) + other.get("stdout_bytes", 0),
        stderr_bytes=sarif.get("stderr_bytes", 0) + other.get("stderr_bytes", 0),
    )
    return facts


def _normalize_challenge_sarif_paths(report, source_root):
    root = source_root.resolve().as_posix().rstrip("/")
    for run in report.get("runs", []):
        _deep_audit_io._normalize_challenge_run(run, root)


def _normalize_challenge_run(run, root):
    _deep_audit_io._normalize_challenge_bases(run, root)
    run.pop("workingDirectory", None)
    for invocation in run.get("invocations", []):
        _deep_audit_io._normalize_challenge_invocation(invocation)
    _deep_audit_io._normalize_challenge_artifact_paths(run, root)
    _deep_audit_io._normalize_challenge_message_paths(run, root)


def _normalize_challenge_bases(run, root):
    bases = run.get("originalUriBaseIds", {})
    for base in bases.values():
        uri = base.get("uri") if isinstance(base, dict) else None
        if isinstance(uri, str) and _deep_audit_io._under_challenge_root(uri, root):
            base["uri"] = "file:///src/"


def _normalize_challenge_invocation(invocation):
    if not isinstance(invocation, dict):
        return
    for key in ("startTimeUtc", "endTimeUtc", "processId", "workingDirectory"):
        invocation.pop(key, None)


def _normalize_challenge_artifact_paths(run, root):
    stack = [run]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            artifact = item.get("artifactLocation")
            uri = artifact.get("uri") if isinstance(artifact, dict) else None
            if isinstance(uri, str):
                artifact["uri"] = _deep_audit_io._challenge_source_uri(uri, root)
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _normalize_challenge_message_paths(run, root):
    stack = [run]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            message = item.get("message")
            if isinstance(message, dict) and isinstance(message.get("text"), str):
                text = message["text"]
                message["text"] = text.replace(root + "/", "/src/").replace(
                    root + "\\", "/src/"
                )
                if message["text"] == root:
                    message["text"] = "/src"
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _under_challenge_root(uri, root):
    clean = _deep_audit_io.unquote(uri).removeprefix("file://")
    return clean == root or clean.startswith(root + "/")


def _challenge_source_uri(uri, root):
    clean = _deep_audit_io.unquote(uri).removeprefix("file://")
    if clean == root:
        return "/src"
    if clean.startswith(root + "/"):
        return "/src/" + clean[len(root) + 1 :]
    return uri


def zap_source_trace_bootstrap(request: dict, inventory: dict) -> str:
    """Build the bounded in-process Python HTTP trace runner for a signed target."""
    from .deep_audit_contract import _validate_zap_target

    fields = {
        "schema",
        "run_id",
        "candidate_sha256",
        "profile_sha256",
        "rule_ids",
        "timeout_seconds",
        "target",
        "route_id",
    }
    _deep_audit_io.exact_keys(request, fields, {"disabled_rule_id"})
    if not fields <= set(request) or set(request) - fields - {"disabled_rule_id"}:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ZAP_SOURCE_TRACE", "native request fields differ"
        )
    target = request["target"]
    _validate_zap_target(target, inventory)
    config = target.get("source_trace")
    if not isinstance(config, dict):
        raise _deep_audit_io.RuntimeAuditError(
            "E_ZAP_SOURCE_TRACE", "signed trace config required"
        )
    sources = _deep_audit_io._zap_trace_sources(inventory)
    routes = _deep_audit_io._zap_trace_routes(target, sources)
    argv = target["argv"]
    script = argv[1]
    script_path = _deep_audit_io.relative_path(script.removeprefix("/src/"))
    if script != "/src/" + script_path or script_path not in sources:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ZAP_SOURCE_TRACE", "bound Python entrypoint required"
        )
    body = {
        "run_id": request["run_id"],
        "candidate_sha256": request["candidate_sha256"],
        "profile_sha256": request["profile_sha256"],
        "target_sha256": _deep_audit_io.digest(target),
        "provider": config["provider"],
        "max_events": config["max_events"],
        "routes": routes,
        "script": script,
        "argv": argv[2:],
    }
    embedded = repr(
        _deep_audit_io.json.dumps(body, sort_keys=True, separators=(",", ":"))
    )
    return _deep_audit_io._ZAP_TRACE_BOOTSTRAP.replace("__TRACE_CONFIG__", embedded)


def _zap_trace_sources(inventory: dict) -> dict[str, str]:
    from .deep_audit_contract import _zap_inventory_sources

    return _zap_inventory_sources(inventory)


def _zap_trace_routes(target: dict, sources: dict[str, str]) -> list[dict]:
    routes = []
    seen = set()
    for route in target["routes"]:
        identity = (route["method"], route["path"])
        if identity in seen:
            raise _deep_audit_io.RuntimeAuditError(
                "E_ZAP_SOURCE_TRACE", "duplicate method and path"
            )
        seen.add(identity)
        bindings = route["source_bindings"]
        if any(
            path not in sources or sources[path] != sha
            for path, sha in bindings.items()
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_ZAP_SOURCE_TRACE", "route source binding differs"
            )
        routes.append(
            {
                "id": route["id"],
                "method": route["method"],
                "path": route["path"],
                "bindings": bindings,
            }
        )
    return routes


def zap_validate_source_trace(
    raw: bytes, request: dict, inventory: dict, snapshot: _deep_audit_io.Path
) -> dict:
    """Validate bounded request-associated trace lines against retained candidate bytes."""
    target, config, routes, parsed = _deep_audit_io._zap_trace_document(
        raw, request, inventory
    )
    observations = _deep_audit_io._zap_trace_observations(
        parsed, routes, inventory, snapshot
    )
    if not observations:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ZAP_SOURCE_TRACE", "nonempty trace required"
        )
    normalized = [
        {
            "route_id": route,
            "path": path,
            "source_sha256": sha,
            "lines": sorted(numbers),
        }
        for (route, path, sha), numbers in sorted(observations.items())
    ]
    return {
        "schema": "factory.zap-source-trace.normalized.v1",
        "run_id": request["run_id"],
        "candidate_sha256": request["candidate_sha256"],
        "profile_sha256": request["profile_sha256"],
        "target_sha256": _deep_audit_io.digest(target),
        "provider": config["provider"],
        "raw_sha256": _deep_audit_io.sha256_bytes(raw),
        "observations": normalized,
        "claim_boundary": "in-process observed request-associated lines, not authenticity/full branches",
    }


def _zap_trace_document(raw: bytes, request: dict, inventory: dict):
    from .deep_audit_contract import _validate_zap_target

    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 4 * 1024 * 1024:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ZAP_SOURCE_TRACE", "trace byte budget exceeded"
        )
    if not raw.endswith(b"\n") or not isinstance(request, dict):
        raise _deep_audit_io.RuntimeAuditError(
            "E_ZAP_SOURCE_TRACE", "complete trace and request required"
        )
    target = request.get("target")
    _validate_zap_target(target, inventory)
    config = target.get("source_trace", {})
    sources = _deep_audit_io._zap_trace_sources(inventory)
    routes = _deep_audit_io._zap_trace_routes(target, sources)
    lines = raw.splitlines()
    if not lines or len(lines) > config["max_events"] + 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ZAP_SOURCE_TRACE", "trace row budget exceeded"
        )
    parsed = []
    for line in lines:
        row = _deep_audit_io.strict_json(line)
        if _deep_audit_io.canonical_bytes(row) != line:
            raise _deep_audit_io.RuntimeAuditError(
                "E_ZAP_SOURCE_TRACE", "noncanonical trace row"
            )
        parsed.append(row)
    expected = {
        "kind": "header",
        "schema": "factory.zap-source-trace.v1",
        "run_id": request["run_id"],
        "candidate_sha256": request["candidate_sha256"],
        "profile_sha256": request["profile_sha256"],
        "target_sha256": _deep_audit_io.digest(target),
        "provider": config["provider"],
        "route_ids": sorted(r["id"] for r in routes),
        "max_events": config["max_events"],
    }
    if parsed[0] != expected:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ZAP_SOURCE_TRACE", "trace header binding differs"
        )
    return target, config, routes, parsed[1:]


def _zap_trace_observations(rows, routes, inventory, snapshot):
    sources = _deep_audit_io._zap_trace_sources(inventory)
    route_map = {route["id"]: route for route in routes}
    source_lines = {}
    seen = set()
    observations = {}
    for row in rows:
        if row.get("overflow") is True:
            raise _deep_audit_io.RuntimeAuditError(
                "E_ZAP_SOURCE_TRACE", "trace overflow marker present"
            )
        _deep_audit_io.exact_keys(row, {"route_id", "path", "source_sha256", "line"})
        route_id = _deep_audit_io.require_str(row["route_id"], "route_id", maximum=64)
        path = _deep_audit_io.relative_path(row["path"])
        source_hash = _deep_audit_io.require_digest(
            row["source_sha256"], "source_sha256"
        )
        line_no = row["line"]
        route = route_map.get(route_id)
        if (
            route is None
            or route["bindings"].get(path) != source_hash
            or sources.get(path) != source_hash
            or type(line_no) is not int
            or line_no < 1
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_ZAP_SOURCE_TRACE", "trace event binding differs"
            )
        key = (route_id, path, source_hash, line_no)
        if key in seen:
            raise _deep_audit_io.RuntimeAuditError(
                "E_ZAP_SOURCE_TRACE", "duplicate trace event"
            )
        seen.add(key)
        binding = (path, source_hash)
        if binding not in source_lines:
            source = _deep_audit_io.bound_bytes(
                snapshot, {"path": path, "sha256": source_hash}
            )
            try:
                encoding, _ = _deep_audit_io.tokenize.detect_encoding(
                    iter(source.splitlines(keepends=True)).__next__
                )
                source_lines[binding] = len(source.decode(encoding).splitlines())
            except (SyntaxError, UnicodeError, StopIteration) as exc:
                raise _deep_audit_io.RuntimeAuditError(
                    "E_ZAP_SOURCE_TRACE", "invalid bound Python source"
                ) from exc
        if line_no > source_lines[binding]:
            raise _deep_audit_io.RuntimeAuditError(
                "E_ZAP_SOURCE_TRACE", "trace line exceeds source"
            )
        observations.setdefault((route_id, path, source_hash), set()).add(line_no)
    return observations


_ZAP_TRACE_BOOTSTRAP = r"""import json, os, runpy, sys, threading
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

CONFIG = json.loads(__TRACE_CONFIG__)
LIMIT = 4 * 1024 * 1024
TRACE_PATH = "/trace/events.jsonl"
if os.path.islink("/trace") or not os.path.isdir("/trace"):
    raise RuntimeError("trace directory unavailable")
fd = os.open(TRACE_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
if not __import__("stat").S_ISREG(os.fstat(fd).st_mode):
    raise RuntimeError("trace file is not regular")
routes = {(r["method"], r["path"]): r for r in CONFIG["routes"]}
route_by_id = {r["id"]: r for r in CONFIG["routes"]}
header = {"kind":"header", "schema":"factory.zap-source-trace.v1", "run_id":CONFIG["run_id"],
 "candidate_sha256":CONFIG["candidate_sha256"], "profile_sha256":CONFIG["profile_sha256"],
 "target_sha256":CONFIG["target_sha256"], "provider":CONFIG["provider"],
 "route_ids":sorted(route_by_id), "max_events":CONFIG["max_events"]}
lock = threading.Lock()
context = threading.local()
seen = set()
path_cache = {}
size = 0
count = 0
failed = False

def encoded(row):
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"

def invalidate(reason):
    global failed
    failed = True
    try:
        marker = encoded({"overflow": True, "reason": reason})
        if size + len(marker) <= LIMIT:
            os.write(fd, marker)
    finally:
        os._exit(70)

def write_row(row, counted):
    global size, count
    raw = encoded(row)
    with lock:
        if failed:
            return
        if (counted and count >= CONFIG["max_events"]) or size + len(raw) > LIMIT - 256:
            invalidate("event_budget")
        try:
            written = os.write(fd, raw)
            if written != len(raw):
                invalidate("short_write")
        except BaseException:
            invalidate("write_failure")
        size += len(raw)
        if counted:
            count += 1

write_row(header, False)
local = threading.local()
original_parse = BaseHTTPRequestHandler.parse_request
original_handle = BaseHTTPRequestHandler.handle_one_request

def parse_request(self):
    ok = original_parse(self)
    if ok:
        route = routes.get((self.command, urlsplit(self.path).path))
        local.route_id = route["id"] if route else None
    return ok

def handle_one_request(self):
    try:
        return original_handle(self)
    finally:
        local.route_id = None

BaseHTTPRequestHandler.parse_request = parse_request
BaseHTTPRequestHandler.handle_one_request = handle_one_request

def trace(frame, event, arg):
    route_id = getattr(local, "route_id", None)
    if event == "call":
        if not route_id:
            return None
        filename = frame.f_code.co_filename
        path = path_cache.get(filename)
        if path is None:
            canonical = os.path.realpath(filename)
            path = canonical[5:] if canonical.startswith("/src/") else ""
            path_cache[filename] = path
        return trace if path in route_by_id[route_id]["bindings"] else None
    if event == "line" and route_id:
        filename = frame.f_code.co_filename
        path = path_cache.get(filename)
        if path is None:
            canonical = os.path.realpath(filename)
            path = canonical[5:] if canonical.startswith("/src/") else ""
            path_cache[filename] = path
        sha = route_by_id[route_id]["bindings"].get(path)
        if sha:
            key = (route_id, path, frame.f_lineno)
            with lock:
                fresh = key not in seen
                if fresh:
                    seen.add(key)
            if fresh:
                write_row({"route_id":route_id, "path":path, "source_sha256":sha, "line":frame.f_lineno}, True)
    return trace

script = CONFIG["script"]
if os.path.realpath(script) != script or not script.startswith("/src/"):
    raise RuntimeError("entrypoint path differs")
sys.path.insert(0, os.path.dirname(script))
sys.argv = [script] + CONFIG["argv"]
sys.settrace(trace)
threading.settrace(trace)
runpy.run_path(script, run_name="__main__")
"""
