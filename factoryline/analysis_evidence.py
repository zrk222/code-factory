"""Vendor-neutral, deterministic SARIF evidence adapter.

The adapter reads a user-selected local SARIF artifact. It never starts an
analyzer, contacts a vendor, modifies source, or treats a report as approval.
"""

from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
from typing import Any
from urllib.parse import unquote, urlparse

from .runtime_audit_common import canonical_bytes, _stable_read_identity
from .deep_audit_io import local_file, strict_json
from .audit_trace import verify_audit_trace
from .assembly_process import run_cli_detailed


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
SPAN_EVALUATION_SCHEMA = "factory.span-evaluation.v1"
SPAN_BINDING_SCHEMA = "factory.span-evaluation.binding-request.v1"
SPAN_REQUEST_SCHEMA = "factory.span-evaluation.request.v1"
_SPAN_ROLES = {"tool", "model", "prompt", "rubric", "dataset", "policy"}
_SPAN_OPTIONAL_ROLES = {
    "baseline",
    "candidate_cohort",
    "regression_policy",
    "calibration_dataset",
    "assignments",
    "annotations",
    "judgments",
    "adjudications",
    "sampling",
    "rollout",
    "recovery",
    "deployment_control",
    "killswitch_control",
    "rollback_control",
    "semantic_evidence",
    "span_policy",
}
_SPAN_ARTIFACT_LIMIT = 2_000_000
_SPAN_TOTAL_LIMIT = 20_000_000


def _span_incomplete(code: str, detail: str) -> dict[str, Any]:
    return {"state": "INCOMPLETE", "errors": [{"code": code, "detail": detail}]}


def _span_read(
    root: Path,
    descriptor: object,
    seen: set[str],
    *,
    parse: bool = True,
    include_bytes: bool = False,
) -> tuple[str, str, Any, int]:
    if not isinstance(descriptor, Mapping) or set(descriptor) != {"path", "sha256"}:
        raise AnalysisEvidenceError("TRACE_UNBOUND", "artifact descriptor is invalid")
    path = local_file(root, descriptor["path"])
    relative = path.relative_to(root.resolve()).as_posix()
    if relative in seen:
        raise AnalysisEvidenceError("TRACE_UNBOUND", "artifact paths must be unique")
    size = path.stat().st_size
    if size > _SPAN_ARTIFACT_LIMIT:
        raise AnalysisEvidenceError("TRACE_UNBOUND", "artifact exceeds 2000000 bytes")
    with path.open("rb") as stream:
        before = path.stat()
        opened = os.fstat(stream.fileno())
        raw = stream.read(_SPAN_ARTIFACT_LIMIT + 1)
        after = os.fstat(stream.fileno())
    if len(raw) > _SPAN_ARTIFACT_LIMIT or not _stable_read_identity(
        before, opened, after, path.stat(), windows=os.name == "nt"
    ):
        raise AnalysisEvidenceError(
            "TRACE_UNBOUND", "artifact changed or exceeded its byte bound"
        )
    if sha256(raw).hexdigest() != descriptor["sha256"]:
        raise AnalysisEvidenceError("TRACE_UNBOUND", "artifact hash is stale")
    body = raw if include_bytes else strict_json(raw) if parse else None
    return relative, sha256(raw).hexdigest(), body, size


def _span_binding_rows(workspace: Path, request: Mapping[str, Any]) -> dict[str, Any]:
    artifacts, sources = request["artifacts"], request["sources"]
    if (
        not isinstance(artifacts, Mapping)
        or not _SPAN_ROLES <= set(artifacts)
        or not set(artifacts) <= _SPAN_ROLES | _SPAN_OPTIONAL_ROLES
    ):
        raise AnalysisEvidenceError(
            "TRACE_UNBOUND", "artifact roles are missing or unknown"
        )
    if not isinstance(sources, list) or not 1 <= len(sources) <= 20:
        raise AnalysisEvidenceError(
            "TRACE_UNBOUND", "one to twenty source descriptors required"
        )
    entries = [
        ("trace", request["trace"], True),
        ("candidate", request["candidate"], True),
    ]
    entries.extend((f"source:{i}", item, False) for i, item in enumerate(sources))
    entries.extend((role, item, True) for role, item in artifacts.items())
    rows, seen, total = {}, set(), 0
    for role, descriptor, parse in entries:
        path, digest, body, size = _span_read(workspace, descriptor, seen, parse=parse)
        seen.add(path)
        total += size
        if total > _SPAN_TOTAL_LIMIT:
            raise AnalysisEvidenceError(
                "TRACE_UNBOUND", "unique evidence exceeds 20000000 bytes"
            )
        rows[role] = {"path": path, "sha256": digest, "body": body}
    return rows


def _verify_span_identity(
    workspace: Path, rows: Mapping[str, Any]
) -> tuple[dict, dict[str, str]]:
    trace, candidate = rows["trace"]["body"], rows["candidate"]["body"]
    if not verify_audit_trace(trace)["valid"] or candidate != trace["candidate"]:
        raise AnalysisEvidenceError(
            "TRACE_UNBOUND", "trace or candidate binding is invalid"
        )
    sources = {
        row["path"]: row["sha256"]
        for role, row in rows.items()
        if role.startswith("source:")
    }
    if sources != trace["changed_files"]:
        raise AnalysisEvidenceError(
            "TRACE_UNBOUND", "source bytes do not match verified trace"
        )
    result = run_cli_detailed(
        "git", ["rev-parse", "HEAD"], workspace, timeout=5, max_stream_bytes=4096
    )
    if not (
        result.get("ok")
        and result.get("cleanup_confirmed")
        and result.get("streams_closed")
        and result.get("stdout", b"").decode(errors="replace").strip()
        == candidate.get("commit")
    ):
        raise AnalysisEvidenceError(
            "TRACE_UNBOUND", "current Git commit differs from bound candidate"
        )
    return trace, sources


def _validate_span_versions(
    rows: Mapping[str, Any], applicability: Mapping[str, Any]
) -> None:
    for role in _SPAN_ROLES - {"model"}:
        body = rows[role]["body"]
        if not _span_versioned(body):
            raise AnalysisEvidenceError(
                "TRACE_UNBOUND", f"{role} artifact needs a version"
            )
    model = rows["model"]["body"]
    if applicability["model"] == "applicable":
        valid = isinstance(model, Mapping) and all(
            isinstance(model.get(key), str) and model[key].strip()
            for key in ("id", "version")
        )
    else:
        valid = (
            isinstance(model, Mapping)
            and set(model) == {"state", "rationale"}
            and model.get("state") == "NOT_APPLICABLE"
            and isinstance(model.get("rationale"), str)
            and bool(model["rationale"].strip())
        )
    if not valid:
        raise AnalysisEvidenceError(
            "TRACE_UNBOUND", "model identity or reviewed N/A is invalid"
        )
    for role, row in rows.items():
        body = row["body"]
        if role in _SPAN_OPTIONAL_ROLES and not _span_versioned(body):
            raise AnalysisEvidenceError(
                "TRACE_UNBOUND", f"{role} artifact needs a version"
            )


def _span_versioned(body: object) -> bool:
    if not isinstance(body, Mapping):
        return False
    version = body.get("version")
    schema = body.get("schema")
    return (isinstance(version, str) and bool(version.strip())) or (
        isinstance(schema, str)
        and re.fullmatch(r"factory\.[a-z0-9.-]+\.v[1-9][0-9]*", schema) is not None
    )


def validate_evaluation_bindings(
    root: Path, request: Mapping[str, Any]
) -> dict[str, Any]:
    """Re-read hash-bound local artifacts; integrity is not producer authentication."""
    try:
        return _validate_evaluation_bindings(root, request)
    except (AnalysisEvidenceError, OSError, ValueError, TypeError, KeyError) as exc:
        code = getattr(exc, "code", "TRACE_UNBOUND")
        return _span_incomplete(
            code,
            "required trace, candidate, source, or policy evidence is unavailable or stale",
        )


def _validate_evaluation_bindings(
    root: Path, request: Mapping[str, Any]
) -> dict[str, Any]:
    if (
        not isinstance(request, Mapping)
        or set(request)
        != {"schema", "trace", "candidate", "sources", "artifacts", "applicability"}
        or request.get("schema") != SPAN_BINDING_SCHEMA
    ):
        raise AnalysisEvidenceError(
            "TRACE_UNBOUND", "binding request schema or fields are invalid"
        )
    workspace = Path(root).resolve()
    rows = _span_binding_rows(workspace, request)
    trace, source_hashes = _verify_span_identity(workspace, rows)
    candidate = rows["candidate"]["body"]
    artifacts = request["artifacts"]
    applicability = request["applicability"]
    if not isinstance(applicability, Mapping) or set(applicability) != {"model"}:
        raise AnalysisEvidenceError(
            "TRACE_UNBOUND", "model applicability declaration required"
        )
    if applicability["model"] not in {"applicable", "not_applicable"}:
        raise AnalysisEvidenceError(
            "TRACE_UNBOUND",
            "non-model applicability requires a separately reviewed declaration",
        )
    _validate_span_versions(rows, applicability)
    return {
        "state": "BOUND_LOCAL_EVIDENCE",
        "errors": [],
        "trace": trace,
        "candidate": candidate,
        "source_hashes": source_hashes,
        "artifacts": {role: value for role, value in rows.items() if role in artifacts},
        "binding_sha256": sha256(
            canonical_bytes(
                {key: value for key, value in request.items() if key != "artifacts"}
            )
            + canonical_bytes({role: row["sha256"] for role, row in rows.items()})
        ).hexdigest(),
        "authority": "none",
    }


def _span_numeric(
    span: Mapping[str, Any], dataset: Mapping[str, Any]
) -> dict[str, Any]:
    fact = dataset.get("numeric_facts", {}).get(span.get("span_id"))
    claim = span.get("numeric")
    if not isinstance(fact, Mapping) or not isinstance(claim, Mapping):
        return {
            "state": "INCOMPLETE",
            "code": "NUMERIC_UNGROUNDED",
            "reason": "bound numeric fact or span claim is missing",
        }
    keys = {"value", "unit", "numerator", "denominator", "precision"}
    if set(fact) != keys or set(claim) != keys:
        return {
            "state": "FAIL",
            "code": "NUMERIC_UNGROUNDED",
            "reason": "numeric schema differs from the closed contract",
        }
    values = [
        item[key]
        for item in (fact, claim)
        for key in ("value", "numerator", "denominator")
    ]
    if (
        any(
            isinstance(v, bool)
            or not isinstance(v, (int, float))
            or not math.isfinite(v)
            for v in values
        )
        or fact["denominator"] == 0
        or claim["denominator"] == 0
        or not isinstance(fact["unit"], str)
        or not 1 <= len(fact["unit"]) <= 80
    ):
        return {
            "state": "FAIL",
            "code": "NUMERIC_UNGROUNDED",
            "reason": "numeric values must be finite and denominator nonzero",
        }
    precision = fact["precision"]
    if (
        type(precision) is not int
        or not 0 <= precision <= 18
        or claim["precision"] != precision
    ):
        return {
            "state": "FAIL",
            "code": "NUMERIC_UNGROUNDED",
            "reason": "declared precision is invalid or mismatched",
        }
    from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN

    try:
        quantum = Decimal(1).scaleb(-precision)
        expected = (
            Decimal(str(fact["numerator"])) / Decimal(str(fact["denominator"]))
        ).quantize(quantum, rounding=ROUND_HALF_EVEN)
        matches = (
            Decimal(str(fact["value"])).quantize(quantum)
            == expected
            == Decimal(str(claim["value"])).quantize(quantum)
            and claim["unit"] == fact["unit"]
            and claim["numerator"] == fact["numerator"]
            and claim["denominator"] == fact["denominator"]
        )
    except (InvalidOperation, ZeroDivisionError, OverflowError):
        matches = False
    return {
        "state": "PASS" if matches else "FAIL",
        "code": "NUMERIC_GROUNDED" if matches else "NUMERIC_UNGROUNDED",
        "reason": "numeric claim matches bound local reference"
        if matches
        else "value, unit, denominator, or precision differs from bound reference",
    }


def _span_context(
    span: Mapping[str, Any],
    rubric: Mapping[str, Any],
    dataset: Mapping[str, Any],
    bound: Mapping[str, Any],
) -> dict[str, Any]:
    required = rubric.get("required_context_ids")
    refs = span.get("context_refs")
    if (
        not isinstance(required, list)
        or not all(isinstance(item, str) for item in required)
        or not isinstance(refs, list)
        or not all(isinstance(item, str) for item in refs)
    ):
        return {
            "state": "INCOMPLETE",
            "code": "CONTEXT_INCOMPLETE",
            "omitted": [],
            "contradicted": [],
        }
    evidence = dataset.get("context_evidence")
    if not isinstance(evidence, Mapping):
        return {
            "state": "INCOMPLETE",
            "code": "CONTEXT_INCOMPLETE",
            "omitted": list(required),
            "contradicted": [],
        }
    valid = set()
    bound_hashes = {
        **bound["source_hashes"],
        **{item["path"]: item["sha256"] for item in bound["artifacts"].values()},
    }
    for key, item in evidence.items():
        if (
            isinstance(item, Mapping)
            and set(item) == {"path", "sha256"}
            and isinstance(item["path"], str)
            and _is_sha(item["sha256"])
            and bound_hashes.get(item["path"]) == item["sha256"]
        ):
            valid.add(key)
    omitted = sorted(set(required) - set(refs))
    omitted.extend(sorted(set(refs) - valid))
    contradicted_raw = span.get("contradicted_context_ids", [])
    if not isinstance(contradicted_raw, list) or not all(
        isinstance(item, str) for item in contradicted_raw
    ):
        return {
            "state": "INCOMPLETE",
            "code": "CONTEXT_INCOMPLETE",
            "omitted": omitted,
            "contradicted": [],
        }
    contradicted = sorted(set(contradicted_raw) & set(required))
    state = "FAIL" if contradicted else "INCOMPLETE" if omitted else "PASS"
    return {
        "state": state,
        "code": "CONTEXT_INCOMPLETE" if state != "PASS" else "CONTEXT_COVERED",
        "omitted": omitted,
        "contradicted": contradicted,
        "semantic_correctness": "UNKNOWN",
    }


def _span_tool(span: Mapping[str, Any], tools: Mapping[str, Any]) -> dict[str, Any]:
    contracts = tools.get("tools", {})
    tool = span.get("tool")
    contract = (
        contracts.get(tool.get("name"))
        if isinstance(tool, Mapping) and isinstance(contracts, Mapping)
        else None
    )
    result = tools.get("results", {}).get(span.get("span_id"))
    if not isinstance(contract, Mapping) or not isinstance(result, Mapping):
        return {
            "state": "INCOMPLETE",
            "code": "TOOL_SILENT_FAILURE",
            "reason": "bound tool contract/result evidence missing",
        }
    if (
        result.get("status") not in {"SUCCESS", "ERROR"}
        or type(result.get("result_present")) is not bool
        or type(result.get("output_bytes")) is not int
        or result["output_bytes"] < 0
        or type(contract.get("allow_empty")) is not bool
        or type(contract.get("result_required")) is not bool
        or type(contract.get("state_required")) is not bool
    ):
        return {
            "state": "INCOMPLETE",
            "code": "TOOL_SILENT_FAILURE",
            "reason": "bound tool result or empty-output contract is invalid",
        }
    required = (
        contract.get("result_required") is True
        or contract.get("state_required") is True
    )
    empty = result.get("output_bytes") == 0
    silent = required and (
        result.get("result_present") is not True
        or (
            contract.get("state_required") is True
            and result.get("observed_state") is None
        )
    )
    denied_empty = empty and contract.get("allow_empty") is not True
    failed = result.get("status") == "SUCCESS" and (silent or denied_empty)
    if result["status"] == "ERROR":
        return {
            "state": "PASS",
            "code": "TOOL_ERROR_OBSERVED",
            "reason": "tool failure is explicitly present in bound result evidence",
        }
    return {
        "state": "FAIL" if failed else "PASS",
        "code": "TOOL_SILENT_FAILURE" if failed else "TOOL_RESULT_OBSERVED",
        "reason": "successful tool call omitted required output/state"
        if failed
        else "bound tool contract and result agree",
    }


def _span_redundancy(
    span: Mapping[str, Any],
    earlier: list[Mapping[str, Any]],
    tools: Mapping[str, Any],
    candidate_sha256: str,
) -> dict[str, Any]:
    call = span.get("call")
    if not isinstance(call, Mapping):
        return {
            "state": "INCOMPLETE",
            "code": "REDUNDANCY_UNKNOWN",
            "reason": "call facts missing",
        }
    if (
        set(call)
        != {
            "tool",
            "args_sha256",
            "state_sha256",
            "candidate_sha256",
            "freshness_sha256",
        }
        or call.get("candidate_sha256") != candidate_sha256
        or not all(
            _is_sha(call.get(field))
            for field in ("args_sha256", "state_sha256", "freshness_sha256")
        )
    ):
        return {
            "state": "INCOMPLETE",
            "code": "REDUNDANCY_UNKNOWN",
            "reason": "call state or candidate binding is invalid",
        }
    for prior in earlier:
        old = prior.get("call")
        if (
            not isinstance(old, Mapping)
            or old.get("tool") != call.get("tool")
            or old.get("args_sha256") != call.get("args_sha256")
        ):
            continue
        if (
            old.get("state_sha256") == call.get("state_sha256")
            and old.get("candidate_sha256") == call.get("candidate_sha256")
            and old.get("freshness_sha256") == call.get("freshness_sha256")
        ):
            exemptions = tools.get("exemptions", {})
            exemption = (
                exemptions.get(span.get("span_id"))
                if isinstance(exemptions, Mapping)
                else None
            )
            if exemption is not None:
                return {
                    "state": "INCOMPLETE",
                    "code": "REDUNDANCY_UNKNOWN",
                    "reason": "retry or revalidation exemption is not independently verified",
                }
            return {
                "state": "FAIL",
                "code": "TOOL_REDUNDANT",
                "reason": "identical tool and arguments repeated under unchanged state and freshness",
            }
    return {
        "state": "PASS",
        "code": "TOOL_NOT_REDUNDANT",
        "reason": "no matching unchanged prior call",
    }


_SPAN_CRITERIA = ("numeric", "context", "tool", "redundancy")


def _span_policy_reference(
    reference: object, source_hashes: Mapping[str, str], seen: set[str]
) -> dict[str, str]:
    if not isinstance(reference, Mapping) or set(reference) != {"path", "sha256"}:
        raise ValueError("span applicability source reference is invalid")
    path, digest = reference.get("path"), reference.get("sha256")
    if not isinstance(path, str) or source_hashes.get(path) != digest or path in seen:
        raise ValueError("span applicability source reference is invalid")
    seen.add(path)
    return {"path": path, "sha256": digest}


def _span_policy_entry(
    entry: object, source_hashes: Mapping[str, str]
) -> dict[str, Any]:
    if not isinstance(entry, Mapping) or set(entry) != {
        "applicable",
        "reason",
        "references",
    }:
        raise ValueError("span applicability entry is invalid")
    reason, references = entry.get("reason"), entry.get("references")
    if type(entry.get("applicable")) is not bool:
        raise ValueError("span applicability flag is invalid")
    if (
        not isinstance(reason, str)
        or not reason.strip()
        or len(reason.encode("utf-8")) > 1024
    ):
        raise ValueError("span applicability reason is invalid")
    if not isinstance(references, list) or not 1 <= len(references) <= 8:
        raise ValueError("span applicability references are invalid")
    seen: set[str] = set()
    checked = [_span_policy_reference(ref, source_hashes, seen) for ref in references]
    return {"applicable": entry["applicable"], "reason": reason, "references": checked}


def _span_policy_rules(
    spans: list[Mapping[str, Any]],
    artifacts: Mapping[str, Any],
    bound: Mapping[str, Any],
) -> dict[str, dict[str, Any]] | None:
    if "span_policy" not in artifacts:
        return None
    body = artifacts["span_policy"]["body"]
    rules = body.get("rules") if isinstance(body, Mapping) else None
    if (
        not isinstance(body, Mapping)
        or set(body) != {"schema", "rules"}
        or body.get("schema") != "factory.span-applicability.v1"
        or not isinstance(rules, list)
        or len(rules) != len(spans)
    ):
        raise ValueError("span applicability policy is invalid")
    expected_ids = {span["span_id"] for span in spans}
    parsed = {}
    source_hashes = bound["source_hashes"]
    for rule in rules:
        if (
            not isinstance(rule, Mapping)
            or set(rule) != {"span_id", "criteria"}
            or rule.get("span_id") not in expected_ids
            or rule["span_id"] in parsed
            or not isinstance(rule.get("criteria"), Mapping)
            or set(rule["criteria"]) != set(_SPAN_CRITERIA)
        ):
            raise ValueError("span applicability coverage is invalid")
        criteria = {
            name: _span_policy_entry(entry, source_hashes)
            for name, entry in rule["criteria"].items()
        }
        parsed[rule["span_id"]] = criteria
    if set(parsed) != expected_ids:
        raise ValueError("span applicability coverage is incomplete")
    return parsed


def _span_not_applicable(
    span: Mapping[str, Any], criterion: str, entry: Mapping[str, Any]
) -> dict[str, Any]:
    empty = {
        "numeric": span.get("numeric") is None,
        "context": span.get("context_refs") == []
        and span.get("contradicted_context_ids") == [],
        "tool": span.get("tool") is None,
        "redundancy": span.get("call") is None,
    }
    if not empty[criterion]:
        raise ValueError("not-applicable policy hides present criterion facts")
    return {
        "state": "NOT_APPLICABLE",
        "code": "CRITERION_NOT_APPLICABLE",
        "reason": entry["reason"],
        "references": entry["references"],
    }


def _span_criterion(
    span: Mapping[str, Any],
    name: str,
    entry: Mapping[str, Any] | None,
    evaluator: Any,
) -> dict[str, Any]:
    if entry is not None and entry["applicable"] is False:
        return _span_not_applicable(span, name, entry)
    return evaluator()


def evaluate_spans(root: Path, request: Mapping[str, Any]) -> dict[str, Any]:
    """Contain malformed local facts without disclosing artifact contents."""
    try:
        if len(canonical_bytes(request)) > _SPAN_ARTIFACT_LIMIT:
            return _span_incomplete("TRACE_UNBOUND", "request exceeds byte bound")
        return _evaluate_spans(root, request)
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        OverflowError,
        RecursionError,
    ):
        return _span_incomplete(
            "TRACE_UNBOUND", "span facts violate the closed contract"
        )


def _evaluate_spans(root: Path, request: Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate bounded local span facts; semantic correctness and producer identity remain unknown."""
    if (
        not isinstance(request, Mapping)
        or set(request) != {"schema", "binding_request", "spans"}
        or request.get("schema") != SPAN_REQUEST_SCHEMA
    ):
        return _span_incomplete(
            "TRACE_UNBOUND", "span request schema or fields are invalid"
        )
    bound = validate_evaluation_bindings(root, request["binding_request"])
    if bound["state"] != "BOUND_LOCAL_EVIDENCE":
        return {
            **bound,
            "schema": SPAN_EVALUATION_SCHEMA,
            "criteria": [],
            "authority": "none",
        }
    spans = request["spans"]
    if (
        not isinstance(spans, list)
        or not 1 <= len(spans) <= 10_000
        or len({s.get("span_id") for s in spans if isinstance(s, Mapping)})
        != len(spans)
    ):
        return _span_incomplete(
            "TRACE_UNBOUND", "spans exceed bounds or contain invalid/duplicate IDs"
        )
    artifacts = bound["artifacts"]
    policy = _span_policy_rules(spans, artifacts, bound)
    rows = []
    previous_calls = {}
    for index, span in enumerate(spans):
        if not isinstance(span, Mapping) or not isinstance(span.get("span_id"), str):
            return _span_incomplete("TRACE_UNBOUND", "span record is invalid")
        if set(span) != {
            "span_id",
            "numeric",
            "context_refs",
            "contradicted_context_ids",
            "tool",
            "call",
        }:
            return _span_incomplete(
                "TRACE_UNBOUND", "span has unknown or missing fields"
            )
        candidate_sha = sha256(canonical_bytes(bound["candidate"])).hexdigest()
        call_key = canonical_bytes(span.get("call"))
        prior = previous_calls.get(call_key)
        applicability = policy.get(span["span_id"]) if policy is not None else None
        rows.append(
            {
                "span_id": span["span_id"],
                "numeric": _span_criterion(
                    span,
                    "numeric",
                    applicability.get("numeric") if applicability else None,
                    lambda: _span_numeric(span, artifacts["dataset"]["body"]),
                ),
                "context": _span_criterion(
                    span,
                    "context",
                    applicability.get("context") if applicability else None,
                    lambda: _span_context(
                        span,
                        artifacts["rubric"]["body"],
                        artifacts["dataset"]["body"],
                        bound,
                    ),
                ),
                "tool": _span_criterion(
                    span,
                    "tool",
                    applicability.get("tool") if applicability else None,
                    lambda: _span_tool(span, artifacts["tool"]["body"]),
                ),
                "redundancy": _span_criterion(
                    span,
                    "redundancy",
                    applicability.get("redundancy") if applicability else None,
                    lambda: _span_redundancy(
                        span,
                        [prior] if prior else [],
                        artifacts["tool"]["body"],
                        candidate_sha,
                    ),
                ),
            }
        )
        previous_calls[call_key] = span
    states = [
        criterion["state"]
        for row in rows
        for criterion in (
            row["numeric"],
            row["context"],
            row["tool"],
            row["redundancy"],
        )
    ]
    coverage = {
        "evaluated": sum(state in {"PASS", "FAIL"} for state in states),
        "not_applicable": states.count("NOT_APPLICABLE"),
        "incomplete": states.count("INCOMPLETE"),
        "failed": states.count("FAIL"),
        "total": len(states),
    }
    overall = (
        "FAIL"
        if "FAIL" in states
        else "INCOMPLETE"
        if "INCOMPLETE" in states or coverage["evaluated"] == 0
        else "PASS"
    )
    core = {
        "schema": SPAN_EVALUATION_SCHEMA,
        "state": overall,
        "request_sha256": sha256(canonical_bytes(request)).hexdigest(),
        "binding_sha256": bound["binding_sha256"],
        "trace_sha256": bound["trace"]["trace_sha256"],
        "candidate": bound["candidate"],
        "artifact_hashes": {role: item["sha256"] for role, item in artifacts.items()},
        "provenance": "BOUND_LOCAL_EVIDENCE",
        "semantic_correctness": "UNKNOWN_PENDING_JEV",
        "spans": rows,
        "criteria_coverage": coverage,
        "authority": "none",
        "next_actions": [
            "Obtain semantic review separately; local artifact integrity does not authenticate producer identity."
        ],
    }
    return {**core, "evaluation_sha256": sha256(canonical_bytes(core)).hexdigest()}


def evaluate_spans_file(
    root: Path, request_path: Path, expected_sha256: str
) -> dict[str, Any]:
    """Read a bounded workspace request by exact SHA-256, then evaluate its local evidence."""
    try:
        workspace = Path(root).resolve()
        supplied = Path(request_path)
        relative = (
            supplied.resolve().relative_to(workspace)
            if supplied.is_absolute()
            else supplied
        )
        path = local_file(workspace, relative.as_posix())
        if path.stat().st_size > _SPAN_ARTIFACT_LIMIT:
            raise AnalysisEvidenceError(
                "TRACE_UNBOUND", "span request exceeds 2000000 bytes"
            )
        _, _, body, _ = _span_read(
            workspace,
            {"path": path.relative_to(workspace).as_posix(), "sha256": expected_sha256},
            set(),
        )
        return evaluate_spans(workspace, body)
    except (AnalysisEvidenceError, OSError, ValueError, TypeError) as exc:
        return _span_incomplete(
            getattr(exc, "code", "TRACE_UNBOUND"),
            "span request could not be read or verified",
        )


class AnalysisEvidenceError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def evaluate_trace_file(
    root: Path, request_path: Path, expected_sha256: str, *, kind: str = "spans"
) -> dict[str, Any]:
    """Run one local evaluator on exact request bytes; no provider or deployment effects."""
    from .operations import (
        evaluate_judge_calibration,
        evaluate_trace_sampling,
        evaluate_rollout_evidence,
    )
    from .runtime_audit_performance import evaluate_trace_regression

    evaluators = {
        "spans": evaluate_spans,
        "calibration": evaluate_judge_calibration,
        "sampling": evaluate_trace_sampling,
        "regression": evaluate_trace_regression,
        "rollout": evaluate_rollout_evidence,
    }
    if kind not in evaluators:
        return _span_incomplete("TRACE_UNBOUND", "unknown evaluator kind")
    try:
        workspace = Path(root).resolve()
        path = Path(request_path)
        relative = path.relative_to(workspace) if path.is_absolute() else path
        _, _, request, _ = _span_read(
            workspace, {"path": relative.as_posix(), "sha256": expected_sha256}, set()
        )
        return evaluators[kind](workspace, request)
    except (ValueError, TypeError, KeyError, OSError, AttributeError):
        return _span_incomplete(
            "TRACE_UNBOUND", "request or evaluator contract is invalid"
        )


def _read_trace_manifest(path):
    with path.open("rb") as stream:
        before = path.stat()
        opened = os.fstat(stream.fileno())
        raw = stream.read(4097)
        after = os.fstat(stream.fileno())
    if len(raw) > 4096 or not _stable_read_identity(
        before, opened, after, path.stat(), windows=os.name == "nt"
    ):
        raise ValueError("manifest changed or exceeds bound")
    return strict_json(raw)


def trace_evaluation_status(root: Path) -> dict[str, Any]:
    """Project a saved result only when exact-request reevaluation reproduces it."""
    result = {
        "schema": "factory.trace-evaluation-status.v1",
        "state": "MISSING",
        "authority": "none",
        "metrics": {},
        "kind": None,
        "claim_boundary": "Local recorded evidence; producer identity and semantic accuracy are not authenticated.",
        "next_actions": [
            "Run the relevant evaluator and save a bound request/result manifest."
        ],
    }
    try:
        workspace = Path(root).resolve()
        path = local_file(workspace, ".factory/trace-evaluation/latest.json")
        manifest = _read_trace_manifest(path)
        if (
            set(manifest) != {"schema", "kind", "request", "receipt"}
            or manifest["schema"] != "factory.trace-evaluation-manifest.v1"
        ):
            raise ValueError("manifest fields differ")
        _, _, request, _ = _span_read(workspace, manifest["request"], set())
        _, _, receipt, _ = _span_read(workspace, manifest["receipt"], set())
        kind = manifest["kind"]
        binding = request["binding_request"] if kind == "spans" else request
        current = validate_evaluation_bindings(workspace, binding)
        if (
            current["state"] != "BOUND_LOCAL_EVIDENCE"
            or receipt.get("binding_sha256") != current["binding_sha256"]
        ):
            raise ValueError("saved evaluation is stale")
        _verify_trace_result_hash(receipt, manifest["kind"])
        recomputed = evaluate_trace_file(
            workspace,
            Path(manifest["request"]["path"]),
            manifest["request"]["sha256"],
            kind=kind,
        )
        if recomputed.get("state") == "INCOMPLETE" or canonical_bytes(
            recomputed
        ) != canonical_bytes(receipt):
            raise ValueError("saved result differs from deterministic reevaluation")
        return {
            **result,
            "state": receipt["state"],
            "kind": manifest["kind"],
            "binding_sha256": current["binding_sha256"],
            "metrics": _trace_status_metrics(receipt),
            "next_actions": receipt.get("next_actions", result["next_actions"]),
        }
    except (ValueError, TypeError, KeyError, OSError, AttributeError):
        return {
            **result,
            "state": "INCOMPLETE"
            if (Path(root) / ".factory/trace-evaluation/latest.json").exists()
            else "MISSING",
        }


def _verify_trace_result_hash(receipt: dict[str, Any], kind: str) -> None:
    schemas = {
        "spans": SPAN_EVALUATION_SCHEMA,
        "calibration": "factory.judge-calibration.v1",
        "sampling": "factory.trace-sampling.v1",
        "regression": "factory.trace-regression.v1",
        "rollout": "factory.rollout-evaluation.v1",
    }
    if receipt.get("schema") != schemas.get(kind) or kind not in schemas:
        raise ValueError("result kind mismatch")
    field = (
        "evaluation_sha256" if kind in {"spans", "calibration"} else "receipt_sha256"
    )
    if (
        receipt.get(field)
        != sha256(
            canonical_bytes(
                {key: value for key, value in receipt.items() if key != field}
            )
        ).hexdigest()
    ):
        raise ValueError("result contents differ from receipt hash")


def _trace_status_metrics(receipt: dict[str, Any]) -> dict[str, Any]:
    counts = {
        key: receipt.get(key)
        for key in (
            "eligible",
            "selected",
            "scored",
            "unscored",
            "actual_cost_usd",
            "actual_latency_ms",
        )
    }
    counts["span_count"] = len(receipt.get("spans", []))
    counts["failed_criteria"] = sum(
        row[key]["state"] == "FAIL"
        for row in receipt.get("spans", [])
        for key in ("numeric", "context", "tool", "redundancy")
    )
    counts["regression_breaches"] = sum(
        row["state"] == "FAIL" for row in receipt.get("observations", [])
    )
    counts["per_category"] = receipt.get("per_category", {})
    counts["independence"] = receipt.get("independence", "UNVERIFIED")
    return counts


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
