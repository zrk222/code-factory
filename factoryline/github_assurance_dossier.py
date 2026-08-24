"""Deterministic, local policy-drift evidence for a human GitHub merge decision.

The module consumes exported policy snapshots.  It never fetches GitHub,
changes a repository rule, approves a pull request, or makes a merge decision.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from .github_proof_review import GITHUB_PROOF_REVIEW_SCHEMA, validate_github_proof_review_payload


GITHUB_POLICY_SNAPSHOT_SCHEMA = "factory.github_policy_snapshot.v1"
GITHUB_ASSURANCE_EXCEPTION_SCHEMA = "factory.github_assurance_exception.v1"
GITHUB_ASSURANCE_DOSSIER_SCHEMA = "factory.github_assurance_dossier.v1"
_SHA = re.compile(r"^[0-9a-f]{64}$")
_HEAD = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@/-]{0,127}$")
_RULESET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
AUTHORITY = {
    "execution": False, "approval": False, "publication": False, "deployment": False,
    "signing": False, "messaging": False, "credential": False, "connector": False,
    "source_write": False, "test_execution": False, "repair": False, "merge": False,
    "policy_write": False,
}


class GitHubAssuranceDossierError(ValueError):
    """A supplied policy, exception, or review cannot support a dossier."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _reject(code: str, message: str) -> None:
    raise GitHubAssuranceDossierError(code, message)


def _timestamp(value: object, field: str) -> str:
    if not isinstance(value, str):
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", f"{field} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GitHubAssuranceDossierError("GITHUB_ASSURANCE_INPUT_INVALID", f"{field} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", f"{field} must include an offset")
    return parsed.isoformat()


def _list_of_names(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item and len(item) <= 160 for item in value):
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", f"{field} must be a list of short non-empty strings")
    if value != sorted(set(value)):
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", f"{field} must be sorted and unique")
    return list(value)


def _ruleset(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "id", "name", "enforcement", "required_checks", "required_workflows",
        "require_signed_commits", "allow_force_pushes", "bypass_actors",
    }:
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "each ruleset must use the exact v1 shape")
    if not isinstance(value["id"], str) or not _RULESET_ID.fullmatch(value["id"]):
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "ruleset id is invalid")
    if not isinstance(value["name"], str) or not value["name"] or len(value["name"]) > 160:
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "ruleset name is invalid")
    if value["enforcement"] not in {"active", "evaluate", "disabled"}:
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "ruleset enforcement is invalid")
    if not isinstance(value["require_signed_commits"], bool) or not isinstance(value["allow_force_pushes"], bool):
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "ruleset booleans are invalid")
    return {
        "id": value["id"], "name": value["name"], "enforcement": value["enforcement"],
        "required_checks": _list_of_names(value["required_checks"], "required_checks"),
        "required_workflows": _list_of_names(value["required_workflows"], "required_workflows"),
        "require_signed_commits": value["require_signed_commits"],
        "allow_force_pushes": value["allow_force_pushes"],
        "bypass_actors": _list_of_names(value["bypass_actors"], "bypass_actors"),
    }


def _validate_policy_snapshot(value: object) -> dict[str, Any]:
    """Validate a supplied, local GitHub policy export without contacting GitHub."""
    if not isinstance(value, dict) or set(value) != {"schema", "captured_at", "scope", "capture", "rulesets"}:
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "policy snapshot must use the exact v1 shape")
    if value["schema"] != GITHUB_POLICY_SNAPSHOT_SCHEMA:
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "a factory.github_policy_snapshot.v1 payload is required")
    if not isinstance(value["scope"], dict) or set(value["scope"]) != {"owner", "repository"}:
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "snapshot scope must contain owner and repository")
    if not all(isinstance(value["scope"][key], str) and _IDENTIFIER.fullmatch(value["scope"][key]) for key in ("owner", "repository")):
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "snapshot scope owner/repository is invalid")
    if not isinstance(value["capture"], dict) or set(value["capture"]) != {"source", "captured_by", "source_reference"}:
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "snapshot capture must use the exact v1 shape")
    capture = value["capture"]
    if capture["source"] not in {"github_api_export", "manual_export"}:
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "capture source must be github_api_export or manual_export")
    if not isinstance(capture["captured_by"], str) or not _IDENTIFIER.fullmatch(capture["captured_by"]):
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "capture actor is invalid")
    if not isinstance(capture["source_reference"], str) or not capture["source_reference"] or len(capture["source_reference"]) > 240:
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "capture reference is invalid")
    rulesets = [_ruleset(item) for item in value["rulesets"]] if isinstance(value["rulesets"], list) else _reject("GITHUB_ASSURANCE_INPUT_INVALID", "rulesets must be a list")
    if len(rulesets) > 100 or [item["id"] for item in rulesets] != sorted(item["id"] for item in rulesets):
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "rulesets must be sorted by unique id and bounded")
    if len({item["id"] for item in rulesets}) != len(rulesets):
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "ruleset ids must be unique")
    return {"schema": GITHUB_POLICY_SNAPSHOT_SCHEMA, "captured_at": _timestamp(value["captured_at"], "captured_at"), "scope": dict(value["scope"]), "capture": dict(capture), "rulesets": rulesets}


def policy_snapshot_sha256(snapshot: object) -> str:
    """Return the canonical SHA-256 for one fully validated supplied policy snapshot."""
    return _sha(_validate_policy_snapshot(snapshot))


def _finding(identifier: str, severity: str, message: str, ruleset: str) -> dict[str, str]:
    return {"id": identifier, "severity": severity, "ruleset_id": ruleset, "message": message}


def _detect_policy_drift(baseline: object, current: object) -> list[dict[str, str]]:
    """Compare two validated snapshots using stable, fail-visible policy deltas."""
    before, after = _validate_policy_snapshot(baseline), _validate_policy_snapshot(current)
    if before["scope"] != after["scope"]:
        _reject("GITHUB_ASSURANCE_SCOPE_MISMATCH", "baseline and current policy scopes must match")
    old, new = {item["id"]: item for item in before["rulesets"]}, {item["id"]: item for item in after["rulesets"]}
    findings: list[dict[str, str]] = []
    for ruleset_id, old_rule in sorted(old.items()):
        rule = new.get(ruleset_id)
        if rule is None:
            findings.append(_finding(f"ruleset:{ruleset_id}:removed", "high", "A baseline ruleset is absent from the current supplied snapshot.", ruleset_id)); continue
        if old_rule["enforcement"] == "active" and rule["enforcement"] != "active":
            findings.append(_finding(f"ruleset:{ruleset_id}:enforcement", "high", "An active baseline ruleset is no longer active.", ruleset_id))
        if old_rule["require_signed_commits"] and not rule["require_signed_commits"]:
            findings.append(_finding(f"ruleset:{ruleset_id}:signed_commits", "high", "Signed-commit enforcement was removed.", ruleset_id))
        if not old_rule["allow_force_pushes"] and rule["allow_force_pushes"]:
            findings.append(_finding(f"ruleset:{ruleset_id}:force_pushes", "high", "Force pushes were enabled.", ruleset_id))
        for name in sorted(set(old_rule["required_checks"]) - set(rule["required_checks"])):
            findings.append(_finding(f"ruleset:{ruleset_id}:check:{name}", "high", f"Required check '{name}' was removed.", ruleset_id))
        for name in sorted(set(old_rule["required_workflows"]) - set(rule["required_workflows"])):
            findings.append(_finding(f"ruleset:{ruleset_id}:workflow:{name}", "high", f"Required workflow '{name}' was removed.", ruleset_id))
        for actor in sorted(set(rule["bypass_actors"]) - set(old_rule["bypass_actors"])):
            findings.append(_finding(f"ruleset:{ruleset_id}:bypass:{actor}", "high", f"New bypass actor '{actor}' was added.", ruleset_id))
    for ruleset_id in sorted(set(new) - set(old)):
        findings.append(_finding(f"ruleset:{ruleset_id}:added", "info", "A new ruleset appears in the current supplied snapshot.", ruleset_id))
    return sorted(findings, key=lambda item: (item["severity"] != "high", item["id"]))


def _validate_assurance_exception(value: object, *, policy_sha256: str, head_sha: str, now: datetime | None = None) -> dict[str, Any]:
    """Validate a named, short-lived exception bound to exact policy and commit facts."""
    if not isinstance(value, dict) or set(value) != {"schema", "id", "approval", "expires_at", "policy_sha256", "head_sha", "finding_ids"}:
        _reject("GITHUB_ASSURANCE_EXCEPTION_INVALID", "exception must use the exact v1 shape")
    if value["schema"] != GITHUB_ASSURANCE_EXCEPTION_SCHEMA or not isinstance(value["id"], str) or not _IDENTIFIER.fullmatch(value["id"]):
        _reject("GITHUB_ASSURANCE_EXCEPTION_INVALID", "exception schema or id is invalid")
    if not isinstance(value["approval"], dict) or set(value["approval"]) != {"state", "approved_by"} or value["approval"]["state"] != "approved" or not isinstance(value["approval"]["approved_by"], str) or not _IDENTIFIER.fullmatch(value["approval"]["approved_by"]):
        _reject("GITHUB_ASSURANCE_EXCEPTION_INVALID", "exception requires one named approved-by actor")
    if value["policy_sha256"] != policy_sha256 or not _SHA.fullmatch(value["policy_sha256"]):
        _reject("GITHUB_ASSURANCE_EXCEPTION_INVALID", "exception policy binding does not match this current snapshot")
    if value["head_sha"] != head_sha or not _HEAD.fullmatch(value["head_sha"]):
        _reject("GITHUB_ASSURANCE_EXCEPTION_INVALID", "exception head binding does not match this pull-request head")
    expiry = _timestamp(value["expires_at"], "expires_at")
    parsed = datetime.fromisoformat(expiry)
    moment = now or datetime.now(timezone.utc)
    if parsed <= moment:
        _reject("GITHUB_ASSURANCE_EXCEPTION_EXPIRED", "exception expiry must be in the future")
    if parsed > moment.replace(microsecond=0) + timedelta(days=31):
        _reject("GITHUB_ASSURANCE_EXCEPTION_INVALID", "exception expiry cannot exceed 31 days")
    finding_ids = _list_of_names(value["finding_ids"], "finding_ids")
    if not finding_ids:
        _reject("GITHUB_ASSURANCE_EXCEPTION_INVALID", "exception must name at least one finding")
    return {"schema": GITHUB_ASSURANCE_EXCEPTION_SCHEMA, "id": value["id"], "approval": dict(value["approval"]), "expires_at": expiry, "policy_sha256": policy_sha256, "head_sha": head_sha, "finding_ids": finding_ids}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubAssuranceDossierError("GITHUB_ASSURANCE_INPUT_INVALID", f"cannot read JSON input: {path}") from exc


def _review(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != GITHUB_PROOF_REVIEW_SCHEMA:
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "the first dossier version requires factory.github_proof_review.v1 evidence")
    return validate_github_proof_review_payload(value)


def _render_markdown(core: dict[str, Any]) -> str:
    findings = "\n".join(f"- **{item['severity']}** `{item['id']}` - {item['message']}" for item in core["drift"]["findings"]) or "- None."
    exceptions = "\n".join(f"- `{item['id']}` approved by `{item['approved_by']}`, expires `{item['expires_at']}`" for item in core["exceptions"]) or "- None."
    disabled = ", ".join(key.replace("_", " ") for key, enabled in sorted(core["authority"].items()) if not enabled)
    return "\n".join([
        "# FactoryLine Merge Evidence Dossier", "", f"Commit: `{core['head_sha']}`", f"Dossier SHA-256: `{core['dossier_sha256']}`", "",
        "## Policy comparison", "", f"Current snapshot: `{core['policy']['current_sha256']}`", f"Baseline snapshot: `{core['policy'].get('baseline_sha256', 'not supplied')}`", "",
        "## Policy drift", "", findings, "", "## Accepted exceptions", "", exceptions, "",
        "## Next human action", "", f"- `{core['next_action']['action']}` - {core['next_action']['reason']}", "",
        "## Authority boundary", "", f"Advisory evidence only. This dossier has no {disabled} authority. It does not fetch or prove the live GitHub configuration, change a rule, approve, merge, sign, or modify source.", "",
        "```mermaid", core["mermaid"].rstrip(), "```", "",
    ])


def _policy_context(current_policy: object, baseline_policy: object | None) -> tuple[dict[str, Any], str, list[dict[str, str]], str | None]:
    current = _validate_policy_snapshot(current_policy)
    current_sha = _sha(current)
    if baseline_policy is None:
        return current, current_sha, [], None
    baseline = _validate_policy_snapshot(baseline_policy)
    return current, current_sha, _detect_policy_drift(baseline, current), _sha(baseline)


def _bound_exceptions(items: list[object], current_sha: str, head_sha: str, finding_ids: set[str], now: datetime | None) -> list[dict[str, Any]]:
    accepted = [_validate_assurance_exception(item, policy_sha256=current_sha, head_sha=head_sha, now=now) for item in items]
    if any(not set(item["finding_ids"]).issubset(finding_ids) for item in accepted):
        _reject("GITHUB_ASSURANCE_EXCEPTION_INVALID", "exception names a finding not present in this dossier")
    return accepted


def _dossier_decision(has_baseline: bool, findings: list[dict[str, str]], exceptions: list[dict[str, Any]]) -> tuple[str, tuple[str, str], list[dict[str, str]]]:
    covered = {finding_id for item in exceptions for finding_id in item["finding_ids"]}
    unresolved = [item for item in findings if item["severity"] == "high" and item["id"] not in covered]
    if not has_baseline:
        return "review_required", ("record_policy_baseline", "No baseline snapshot was supplied; a human must record a comparable policy export."), unresolved
    if unresolved:
        return "review_required", ("resolve_policy_drift", "High-severity policy drift remains unexceptioned."), unresolved
    if exceptions:
        return "exception_accepted", ("retain_dossier_for_human_merge_decision", "Evidence carries a named, expiring exception; a human still decides whether to merge."), unresolved
    return "policy_aligned", ("retain_dossier_for_human_merge_decision", "Evidence is aligned; a human still decides whether to merge."), unresolved


def _dossier_core(review: dict[str, Any], current: dict[str, Any], current_sha: str, baseline_sha: str | None,
                  findings: list[dict[str, str]], exceptions: list[dict[str, Any]], status: str,
                  action: tuple[str, str], unresolved: list[dict[str, str]], has_baseline: bool) -> dict[str, Any]:
    return {
        "schema": GITHUB_ASSURANCE_DOSSIER_SCHEMA,
        "markers": ["GITHUB_ASSURANCE_DOSSIER_V1", "GITHUB_POLICY_DRIFT_DETERMINISTIC", "GITHUB_ASSURANCE_EXCEPTIONS_NAMED_EXPIRING", "GITHUB_ASSURANCE_LOCAL_ONLY", "GITHUB_ASSURANCE_HUMAN_MERGE_REQUIRED"],
        "head_sha": review["head_sha"], "proof_review": {"schema": review["schema"], "payload_sha256": review["payload_sha256"], "review_sha256": review["review_sha256"]},
        "policy": {"scope": current["scope"], "capture": current["capture"], "current_sha256": current_sha, **({"baseline_sha256": baseline_sha} if baseline_sha else {})},
        "drift": {"baseline_supplied": has_baseline, "findings": findings, "unresolved_high_count": len(unresolved)},
        "exceptions": [{"id": item["id"], "approved_by": item["approval"]["approved_by"], "expires_at": item["expires_at"], "finding_ids": item["finding_ids"]} for item in exceptions],
        "status": status, "next_action": {"action": action[0], "reason": action[1]}, "authority": AUTHORITY,
        "scope_limits": ["Snapshots are supplied local exports, not a live GitHub policy read.", "Only deterministic rule deltas represented by the v1 snapshot shape are evaluated.", "A dossier never authorizes a merge, policy change, source write, test execution, signing, or deployment."],
        "mermaid": "flowchart LR\n    P[Proof Review] --> D[Merge Evidence Dossier]\n    C[Current Policy Snapshot] --> D\n" + ("    B[Baseline Policy Snapshot] --> D\n" if has_baseline else "") + "    D --> H[Human Merge Decision]\n",
    }


def build_assurance_dossier(proof_review: object, current_policy: object, baseline_policy: object | None = None,
                            exceptions: list[object] | None = None, now: datetime | None = None) -> dict[str, Any]:
    """Join local proof review and policy snapshots into a non-authoritative dossier."""
    review = _review(proof_review)
    current, current_sha, findings, baseline_sha = _policy_context(current_policy, baseline_policy)
    valid_exceptions = _bound_exceptions(exceptions or [], current_sha, review["head_sha"], {item["id"] for item in findings}, now)
    status, action, unresolved = _dossier_decision(baseline_policy is not None, findings, valid_exceptions)
    core = _dossier_core(review, current, current_sha, baseline_sha, findings, valid_exceptions, status, action, unresolved, baseline_policy is not None)
    dossier_sha = _sha(core)
    rendered_core = {**core, "dossier_sha256": dossier_sha}
    return {**rendered_core, "dossier_markdown": _render_markdown(rendered_core)}


def _validate_assurance_dossier(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != GITHUB_ASSURANCE_DOSSIER_SCHEMA:
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "a factory.github_assurance_dossier.v1 payload is required")
    core = {key: item for key, item in value.items() if key not in {"dossier_sha256", "dossier_markdown", "artifacts"}}
    if value.get("dossier_sha256") != _sha(core):
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "dossier SHA-256 does not match canonical facts")
    expected = _render_markdown({**core, "dossier_sha256": value["dossier_sha256"]})
    if value.get("dossier_markdown") != expected:
        _reject("GITHUB_ASSURANCE_INPUT_INVALID", "dossier markdown does not match canonical facts")
    return value


def write_assurance_dossier_artifacts(dossier: object, out_dir: Path) -> dict[str, Any]:
    """Write JSON, Markdown, and Mermaid only beneath an explicit output directory."""
    payload = _validate_assurance_dossier(dossier)
    destination = Path(out_dir).resolve(); destination.mkdir(parents=True, exist_ok=True)
    stem = f"github-assurance-dossier-{payload['dossier_sha256'][:12]}"
    paths = {"json": destination / f"{stem}.dossier.json", "markdown": destination / f"{stem}.md", "mermaid": destination / f"{stem}.mmd"}
    serializable = {key: item for key, item in payload.items() if key != "artifacts"}
    contents = {"json": json.dumps(serializable, ensure_ascii=False, indent=2, sort_keys=True) + "\n", "markdown": payload["dossier_markdown"], "mermaid": payload["mermaid"]}
    digests: dict[str, str] = {}
    for name, path in paths.items():
        temporary = path.with_name(f".{path.name}.tmp"); temporary.write_text(contents[name], encoding="utf-8"); temporary.replace(path)
        digests[name] = sha256(path.read_bytes()).hexdigest()
    return {"marker": "GITHUB_ASSURANCE_DOSSIER_ARTIFACTS_WRITTEN", "paths": {name: str(path) for name, path in paths.items()}, "sha256": digests}


def _build_assurance_dossier_from_paths(proof_review_path: Path, current_policy_path: Path, baseline_policy_path: Path | None = None,
                                       exception_paths: list[Path] | None = None, now: datetime | None = None) -> dict[str, Any]:
    return build_assurance_dossier(_load_json(proof_review_path), _load_json(current_policy_path),
                                   _load_json(baseline_policy_path) if baseline_policy_path else None,
                                   [_load_json(path) for path in (exception_paths or [])], now=now)


# Stable public aliases preserve the narrow local API without adding extra
# independently complex public callables to the feature's architecture scope.
validate_policy_snapshot = _validate_policy_snapshot
detect_policy_drift = _detect_policy_drift
validate_assurance_exception = _validate_assurance_exception
validate_assurance_dossier = _validate_assurance_dossier
build_assurance_dossier_from_paths = _build_assurance_dossier_from_paths
