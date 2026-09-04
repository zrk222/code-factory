"""Deterministic deep-audit decisions over externally bound analyzer evidence.

The execute entry point verifies signatures and re-normalizes reports itself.
The pure evaluator does not authenticate caller-supplied dictionaries. Neither
entry point executes an analyzer or grants approval, execution or release rights.
"""
from __future__ import annotations

from collections import defaultdict
from itertools import islice
from pathlib import Path
import stat

from .deep_audit_contract import verify_deep_audit_plan
from .deep_audit_io import LIMIT, digest, local_file, strict_json
from .deep_audit_sarif import normalize_sarif
from .runtime_audit_common import RuntimeAuditError, canonical_bytes

SCHEMA = "factory.deep-audit-receipt.v1"
SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _reports(plan: dict, supplied: list, field: str) -> dict:
    expected = {item["id"]: item for item in plan["analyzers"]}
    found = {}
    for report in supplied:
        body = {key: value for key, value in report.items() if key != "normalized_sha256"}
        identity = report["analyzer"]
        key = identity["id"]
        if report.get("schema") != "factory.deep-sarif.v1" or report.get("authority") != "none":
            raise RuntimeAuditError("E_DEEP_REPORT", "unexpected normalized report")
        if key not in expected or key in found or digest(body) != report.get("normalized_sha256"):
            raise RuntimeAuditError("E_DEEP_REPORT", "duplicate, unknown or modified report")
        declared = expected[key]
        if identity != {name: declared[name] for name in ("id", "driver", "version")} or report["report_sha256"] != declared[field]["sha256"]:
            raise RuntimeAuditError("E_DEEP_REPORT", "report differs from signed binding")
        found[key] = report
    if set(found) != set(expected):
        raise RuntimeAuditError("E_ANALYZER_INCOMPLETE", "required analyzer evidence missing")
    return found


def _action(code: str, rule: dict | None = None, finding: dict | None = None) -> dict:
    rule, finding = rule or {}, finding or {}
    locations = finding.get("locations", [])
    return {"code": code, "severity": rule.get("severity", "high"),
            "rule_id": rule.get("id", finding.get("rule_id", "")),
            "obligation_id": rule.get("obligation_id", ""),
            "finding_id": finding.get("finding_id", ""),
            "path": locations[0]["path"] if locations else "",
            "remediation": rule.get("remediation", "Restore independently produced evidence and request policy-owner review."),
            "consequence": rule.get("consequence", "The supplied evidence cannot justify readiness.")}


def _canary_actions(plan: dict, reports: dict) -> list:
    actions = []
    for canary in plan["canaries"]:
        findings = reports[canary["analyzer_id"]]["findings"]
        detected = any(item["rule_id"] == canary["rule_id"]
                       and item["native_fingerprint_sha256"] == canary["fingerprint_sha256"]
                       and item["kind"] == "fail" and item["baseline"] != "absent"
                       and not item["suppressed"] for item in findings)
        if not detected:
            action = _action("HOLLOW_DEEP_AUDIT")
            action["canary_id"] = canary["id"]
            action["analyzer_id"] = canary["analyzer_id"]
            actions.append(action)
    return actions


def _ordered_source_sink(flows: list) -> bool:
    for flow in flows:
        source_seen = False
        for step in flow:
            if source_seen and "sink" in step["kinds"]:
                return True
            source_seen = source_seen or "source" in step["kinds"]
    return False


def _finding_actions(rule: dict | None, finding: dict) -> list:
    actions = []
    approved = rule is not None and finding["native_fingerprint_sha256"] in rule["allowed_suppressions"]
    if finding["suppressed"] and not approved:
        actions.append(_action("DEEP_SUPPRESSION_UNAPPROVED", rule, finding))
    if rule is None:
        if finding["level"] == "error" and finding["baseline"] in {"new", "updated", "unbaselined"}:
            actions.append(_action("DEEP_UNKNOWN_ERROR", None, finding))
        return actions
    if finding["trace_depth"] < rule["min_trace_steps"] or (rule["require_source_sink"] and not _ordered_source_sink(finding["flows"])):
        actions.append(_action("DEEP_TRACE_INCOMPLETE", rule, finding))
    return actions


def _clusters(findings: list) -> list:
    grouped = defaultdict(list)
    for finding in findings:
        if finding.get("obligation_id"):
            for path in {item["path"] for item in finding["locations"]}:
                grouped[path].append(finding)
    clusters = []
    for path, members in sorted(grouped.items()):
        obligations = defaultdict(list)
        for finding in members:
            obligations[finding["obligation_id"]].append(finding)
        for obligation, same in sorted(obligations.items()):
            if len({item["analyzer_id"] for item in same}) > 1:
                clusters.append({"kind": "corroboration", "path": path, "obligation_id": obligation,
                                 "findings": sorted(item["finding_id"] for item in same), "claim": "routing_signal_not_causation"})
        if len({item["category"] for item in members}) > 1:
            clusters.append({"kind": "compound_risk", "path": path,
                             "findings": sorted(item["finding_id"] for item in members), "claim": "routing_signal_not_causation"})
    return clusters


def _collect_findings(plan: dict, target: dict, actions: list) -> tuple:
    aliases = {(alias["analyzer_id"], alias["rule_id"]): rule for rule in plan["rules"] for alias in rule["aliases"]}
    findings, counts = [], defaultdict(list)
    for analyzer_id in sorted(target):
        for original in target[analyzer_id]["findings"]:
            finding = dict(original)
            rule = aliases.get((analyzer_id, finding["rule_id"]))
            actions.extend(_finding_actions(rule, finding))
            if rule:
                finding.update(obligation_id=rule["obligation_id"], category=rule["category"], severity=rule["severity"])
                counts[rule["id"]].append(finding)
            findings.append(finding)
            if len(findings) > 20_000 or len(actions) > 20_000:
                raise RuntimeAuditError("E_DEEP_LIMIT", "aggregate finding or action limit exceeded")
    return findings, counts


def _threshold_actions(plan: dict, counts: dict) -> list:
    actions = []
    for rule in plan["rules"]:
        items = counts[rule["id"]]
        introduced = sum(item["baseline"] in {"new", "updated", "unbaselined"} for item in items)
        if len(items) > rule["max_total"] or introduced > rule["max_new"]:
            action = _action("DEEP_RULE_THRESHOLD", rule)
            action.update(total=len(items), introduced=introduced, max_total=rule["max_total"], max_new=rule["max_new"])
            actions.append(action)
    return actions


def evaluate_deep_audit(plan: dict, reports: list, canary_reports: list) -> dict:
    """Evaluate supplied normalized facts without authenticating dictionaries or granting any execution or release authority."""
    target = _reports(plan, reports, "report")
    canaries = _reports(plan, canary_reports, "canary_report")
    actions = _canary_actions(plan, canaries)
    findings, counts = _collect_findings(plan, target, actions)
    actions.extend(_threshold_actions(plan, counts))
    clusters = _clusters(findings)
    if len(actions) > 20_000 or len(clusters) > 20_000:
        raise RuntimeAuditError("E_DEEP_LIMIT", "aggregate action or cluster limit exceeded")
    actions.sort(key=lambda item: (SEVERITY[item["severity"]], item["path"], item["rule_id"], item["code"], item["finding_id"], item.get("canary_id", "")))
    receipt = {"schema": SCHEMA, "candidate_sha256": plan["candidate_sha256"], "plan_payload_sha256": digest(plan),
               "findings": sorted(findings, key=lambda item: item["finding_id"]), "clusters": clusters,
               "repair_queue": actions, "decision": "BLOCKED" if actions else "READY_FOR_HUMAN_REVIEW",
               "report_hashes": {key: value["normalized_sha256"] for key, value in sorted(target.items())},
               "canary_hashes": {key: value["normalized_sha256"] for key, value in sorted(canaries.items())},
               "authority": "none", "claim_boundary": "Supplied analyzer evidence is not proof of defect absence or release approval."}
    return {**receipt, "receipt_sha256": digest(receipt)}


def _write_receipt(root: Path, receipt: dict) -> Path:
    directory = root
    for part in (".factory", "deep-audits"):
        directory = directory / part
        directory.mkdir(exist_ok=True)
        info = directory.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeAuditError("E_PATH_ESCAPE", "receipt directory must not be linked")
    path = directory / (receipt["receipt_sha256"] + ".json")
    raw = canonical_bytes(receipt)
    if len(raw) > LIMIT:
        raise RuntimeAuditError("E_DEEP_LIMIT", "receipt exceeds byte budget")
    try:
        with path.open("xb") as stream:
            stream.write(raw)
    except FileExistsError:
        checked = local_file(root, path.relative_to(root).as_posix())
        with checked.open("rb") as stream:
            if stream.read(LIMIT+1) != raw:
                raise RuntimeAuditError("E_RECEIPT_COLLISION", "existing receipt differs")
    return path


def execute_deep_audit(plan_path: Path, trust_root_path: Path, trust_root_sha256: str, workspace_root: Path) -> dict:
    """Verify signed inputs, normalize exact reports, evaluate policies and persist one non-authorizing audit receipt."""
    checked = verify_deep_audit_plan(plan_path, trust_root_path, trust_root_sha256, workspace_root)
    plan, sources = checked["plan"], checked["source_hashes"]
    targets, canaries = [], []
    for analyzer in plan["analyzers"]:
        targets.append(normalize_sarif(workspace_root, analyzer["report"], analyzer, sources))
        canaries.append(normalize_sarif(workspace_root, analyzer["canary_report"], analyzer, sources))
    receipt = evaluate_deep_audit(plan, targets, canaries)
    if verify_deep_audit_plan(plan_path, trust_root_path, trust_root_sha256, workspace_root) != checked:
        raise RuntimeAuditError("E_INPUT_CHANGED", "inputs changed across evaluation")
    receipt.pop("receipt_sha256")
    for name in ("plan_sha256", "ruleset_sha256", "canary_set_sha256"):
        receipt[name] = checked[name]
    receipt["receipt_sha256"] = digest(receipt)
    path = _write_receipt(Path(workspace_root).resolve(), receipt)
    return {"receipt": receipt, "receipt_path": str(path), "authority": "none"}


def _history(root: Path) -> list:
    directory = root
    for part in (".factory", "deep-audits"):
        directory = directory / part
        if not directory.exists() and not directory.is_symlink():
            return []
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("receipt history must be an unlinked directory")
    paths = list(islice(directory.glob("*.json"), 1025))
    if len(paths) > 1024:
        raise ValueError("receipt history exceeds inspection bound")
    return paths


def _read_receipt(root: Path, path: Path) -> tuple:
    path = local_file(root, path.relative_to(root).as_posix())
    with path.open("rb") as stream:
        raw = stream.read(LIMIT+1)
    if len(raw) > LIMIT:
        raise ValueError("receipt exceeds inspection budget")
    receipt = strict_json(raw)
    claimed = receipt.pop("receipt_sha256")
    if digest(receipt) != claimed or path.stem != claimed or receipt["schema"] != SCHEMA or receipt["authority"] != "none":
        raise ValueError("receipt integrity mismatch")
    expected = "BLOCKED" if receipt["repair_queue"] else "READY_FOR_HUMAN_REVIEW"
    if receipt["decision"] != expected:
        raise ValueError("decision inconsistent with blockers")
    return receipt, claimed, expected


def deep_audit_status(root: Path) -> dict:
    """Read bounded receipt history with tamper checks, never treating a self-hash as signer authentication."""
    root = Path(root).resolve()
    result = {"schema": "factory.deep-audit-status.v1", "state": "NOT_RUN", "authority": "none"}
    try:
        paths = _history(root)
        if not paths:
            return result
        path = max(paths, key=lambda item: (item.stat().st_mtime_ns, item.name))
        receipt, claimed, expected = _read_receipt(root, path)
        return {**result, "state": expected, "receipt_path": str(path), "receipt_sha256": claimed,
                "finding_count": len(receipt["findings"]), "repair_queue": receipt["repair_queue"],
                "verification": "self_hash_only_not_signature_or_freshness"}
    except (OSError, ValueError, KeyError, TypeError):
        return {**result, "state": "INCOMPLETE"}
