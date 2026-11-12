"""Deterministic, advisory convergence audit for external review rounds.

This adapts Atomic's review workflow mechanics without importing or running
Atomic. Reviewer claims remain untrusted input; this module never decides code
correctness or release readiness.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path, PureWindowsPath
import re
import tempfile
import unicodedata
import uuid
from typing import Any


CONTRACT_SCHEMA = "factory.atomic-review-contract.v1"
ROUND_SCHEMA = "factory.atomic-review-round.v1"
RECEIPT_SCHEMA = "factory.atomic-review-convergence.v1"
A2A_HANDOFF_SCHEMA = "factory.a2a.review-handoff.v1"
A2A_SUBMISSION_SCHEMA = "factory.atomic-review-submission.v1"
A2A_VERSION = "1.0.0"
A2A_INPUT_MEDIA_TYPE = "application/vnd.code-factory.review-round+json"
A2A_OUTPUT_MEDIA_TYPE = "application/vnd.code-factory.review-handoff+json"
MAX_BYTES = 1_000_000
MAX_REVIEWERS = 8
MAX_CRITERIA = 64
MAX_FINDINGS = 256
_HASH = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_CODE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
_ORIGINS = {
    "human_confirmed",
    "trusted_source",
    "observed_production",
    "agent_proposed",
}
_ALIGNMENTS = {
    "required_by_objective",
    "consistent_with_objective",
    "beyond_objective",
    "contradicts_objective",
    "unknown",
}


class ReviewConvergenceError(ValueError):
    """Rejected review-convergence input."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _digest(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReviewConvergenceError(
                "E_REVIEW_DUPLICATE_FIELD", f"duplicate JSON field: {key}"
            )
        result[key] = value
    return result


def _workspace_file(root: Path, raw: object, *, exists: bool) -> Path:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise ReviewConvergenceError(
            "E_REVIEW_PATH", "paths must be workspace-relative POSIX paths"
        )
    relative = Path(raw)
    if relative.is_absolute() or PureWindowsPath(raw).drive or ".." in relative.parts:
        raise ReviewConvergenceError("E_REVIEW_PATH", "path escapes the workspace")
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or (exists and not path.is_file()):
        raise ReviewConvergenceError(
            "E_REVIEW_PATH", "missing or escaping workspace path"
        )
    return path


def _read_json(root: Path, raw: object) -> tuple[dict[str, Any], str]:
    path = _workspace_file(root, raw, exists=True)
    try:
        with path.open("rb") as stream:
            payload = stream.read(MAX_BYTES + 1)
        if len(payload) > MAX_BYTES:
            raise ReviewConvergenceError(
                "E_REVIEW_SIZE", f"input exceeds {MAX_BYTES} bytes"
            )
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_fields)
    except ReviewConvergenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ReviewConvergenceError(
            "E_REVIEW_JSON", "input must be valid UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise ReviewConvergenceError(
            "E_REVIEW_SCHEMA", "input root must be a JSON object"
        )
    return value, path.relative_to(root).as_posix()


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReviewConvergenceError(
            "E_REVIEW_SCHEMA",
            f"{label} must contain exactly: {', '.join(sorted(fields))}",
        )
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ReviewConvergenceError(
            "E_REVIEW_SCHEMA", f"{label} must be a bounded identifier"
        )
    return value


def _hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ReviewConvergenceError(
            "E_REVIEW_SCHEMA", f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _contract(
    value: object,
) -> tuple[dict[str, Any], str, dict[str, dict[str, Any]], list[str]]:
    contract = _exact(
        value,
        {
            "schema",
            "contract_id",
            "intent_sha256",
            "origin",
            "reviewer_ids",
            "criteria",
        },
        "review contract",
    )
    if contract["schema"] != CONTRACT_SCHEMA:
        raise ReviewConvergenceError(
            "E_REVIEW_SCHEMA", "unsupported review contract schema"
        )
    _identifier(contract["contract_id"], "contract_id")
    _hash(contract["intent_sha256"], "intent_sha256")
    if not isinstance(contract["origin"], str) or contract["origin"] not in _ORIGINS:
        raise ReviewConvergenceError(
            "E_REVIEW_SCHEMA", "contract origin is unsupported"
        )
    reviewer_ids = contract["reviewer_ids"]
    if (
        not isinstance(reviewer_ids, list)
        or not 1 <= len(reviewer_ids) <= MAX_REVIEWERS
    ):
        raise ReviewConvergenceError(
            "E_REVIEW_LIMIT", f"reviewer_ids must contain 1..{MAX_REVIEWERS} entries"
        )
    reviewers = [_identifier(item, "reviewer_id") for item in reviewer_ids]
    if len(set(reviewers)) != len(reviewers):
        raise ReviewConvergenceError("E_REVIEW_SCHEMA", "reviewer_ids must be unique")
    raw_criteria = contract["criteria"]
    if not isinstance(raw_criteria, list) or not 1 <= len(raw_criteria) <= MAX_CRITERIA:
        raise ReviewConvergenceError(
            "E_REVIEW_LIMIT", f"criteria must contain 1..{MAX_CRITERIA} entries"
        )
    criteria: dict[str, dict[str, Any]] = {}
    for raw in raw_criteria:
        item = _exact(
            raw, {"id", "obligation_id", "statement_sha256", "origin"}, "criterion"
        )
        identifier = _identifier(item["id"], "criterion id")
        _identifier(item["obligation_id"], "obligation_id")
        _hash(item["statement_sha256"], "statement_sha256")
        if (
            not isinstance(item["origin"], str)
            or item["origin"] not in _ORIGINS
            or identifier in criteria
        ):
            raise ReviewConvergenceError(
                "E_REVIEW_SCHEMA", "criterion origin invalid or criterion id duplicated"
            )
        criteria[identifier] = item
    return contract, _digest(contract), criteria, reviewers


def _normalize_round(value: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Accept local JSON or one A2A v1.0 DataPart carrying a CF review round."""
    if value.get("schema") == ROUND_SCHEMA:
        return value, {
            "kind": "local_json",
            "a2a_message_id": None,
            "context_id": None,
            "task_id": None,
        }

    allowed_message_fields = {
        "messageId",
        "contextId",
        "taskId",
        "role",
        "parts",
        "metadata",
        "extensions",
        "referenceTaskIds",
    }
    if set(value) - allowed_message_fields or not {
        "messageId",
        "role",
        "parts",
    }.issubset(value):
        raise ReviewConvergenceError(
            "E_REVIEW_A2A_MESSAGE",
            "A2A input must be one supported Message with a DataPart",
        )
    message_id = value["messageId"]
    if (
        not isinstance(message_id, str)
        or not message_id.strip()
        or len(message_id) > 256
    ):
        raise ReviewConvergenceError("E_REVIEW_A2A_MESSAGE", "A2A messageId is invalid")
    context_id = value.get("contextId")
    task_id = value.get("taskId")
    if context_id is None:
        raise ReviewConvergenceError(
            "E_REVIEW_A2A_MESSAGE", "A2A agent reply requires contextId"
        )
    for label, identifier in (("contextId", context_id), ("taskId", task_id)):
        if identifier is not None and (
            not isinstance(identifier, str)
            or not identifier.strip()
            or len(identifier) > 256
        ):
            raise ReviewConvergenceError(
                "E_REVIEW_A2A_MESSAGE", f"A2A {label} is invalid"
            )
    if "metadata" in value and not isinstance(value["metadata"], dict):
        raise ReviewConvergenceError(
            "E_REVIEW_A2A_MESSAGE", "A2A message metadata must be an object"
        )
    for label in ("extensions", "referenceTaskIds"):
        if label in value and (
            not isinstance(value[label], list)
            or any(
                not isinstance(item, str) or not item.strip() or len(item) > 512
                for item in value[label]
            )
        ):
            raise ReviewConvergenceError(
                "E_REVIEW_A2A_MESSAGE", f"A2A {label} must be bounded strings"
            )
    if value["role"] != "ROLE_AGENT":
        raise ReviewConvergenceError(
            "E_REVIEW_A2A_MESSAGE", "A2A reply role must be the declared ROLE_AGENT"
        )
    parts = value["parts"]
    if not isinstance(parts, list) or len(parts) != 1 or not isinstance(parts[0], dict):
        raise ReviewConvergenceError(
            "E_REVIEW_A2A_MESSAGE", "A2A review reply must contain exactly one DataPart"
        )
    part = parts[0]
    if set(part) - {"data", "mediaType", "metadata", "filename"} or "data" not in part:
        raise ReviewConvergenceError(
            "E_REVIEW_A2A_MESSAGE", "A2A part is not a supported DataPart"
        )
    media_type = part.get("mediaType")
    if media_type is not None and (
        not isinstance(media_type, str)
        or media_type not in {"application/json", A2A_INPUT_MEDIA_TYPE}
    ):
        raise ReviewConvergenceError(
            "E_REVIEW_A2A_MESSAGE", "A2A review DataPart mediaType is unsupported"
        )
    if "metadata" in part and not isinstance(part["metadata"], dict):
        raise ReviewConvergenceError(
            "E_REVIEW_A2A_MESSAGE", "A2A part metadata must be an object"
        )
    if "filename" in part and not isinstance(part["filename"], str):
        raise ReviewConvergenceError(
            "E_REVIEW_A2A_MESSAGE", "A2A part filename must be a string"
        )
    data = part["data"]
    if not isinstance(data, dict):
        raise ReviewConvergenceError(
            "E_REVIEW_A2A_MESSAGE", "A2A review DataPart data must be an object"
        )
    if data.get("schema") == ROUND_SCHEMA:
        round_value = data
    elif data.get("schema") == A2A_SUBMISSION_SCHEMA:
        submission = _exact(
            data,
            {"schema", "round_id", "contract_sha256", "candidate_sha256", "review"},
            "A2A review submission",
        )
        round_value = {
            "schema": ROUND_SCHEMA,
            "round_id": submission["round_id"],
            "contract_sha256": submission["contract_sha256"],
            "candidate_sha256": submission["candidate_sha256"],
            "reviews": [submission["review"]],
        }
    else:
        raise ReviewConvergenceError(
            "E_REVIEW_A2A_MESSAGE",
            "A2A DataPart schema must be a CF review round or submission",
        )
    return round_value, {
        "kind": "a2a_message",
        "protocol_version": A2A_VERSION,
        "a2a_message_id": message_id,
        "context_id": context_id,
        "task_id": task_id,
        "role_declared": value["role"],
        "sender_identity_verified": False,
    }


def _normalized(value: str) -> str:
    value = unicodedata.normalize("NFKC", value).casefold()
    value = re.sub(r"^\s*\[p[0-3]\]\s*", "", value)
    return " ".join(value.split())


def _finding(
    raw: object, criterion_id: str, reviewer_id: str, evidence_sha256: str
) -> dict[str, Any]:
    item = _exact(
        raw, {"code", "title", "path", "symbol", "priority", "alignment"}, "finding"
    )
    code, title = item["code"], item["title"]
    if not isinstance(code, str) or not _CODE.fullmatch(code):
        raise ReviewConvergenceError("E_REVIEW_CELL", "finding code is invalid")
    if not isinstance(title, str) or not title.strip() or len(title) > 500:
        raise ReviewConvergenceError(
            "E_REVIEW_CELL", "finding title must contain 1..500 characters"
        )
    path = item["path"]
    if path is not None:
        if (
            not isinstance(path, str)
            or not path
            or "\\" in path
            or Path(path).is_absolute()
            or PureWindowsPath(path).drive
            or ".." in Path(path).parts
        ):
            raise ReviewConvergenceError(
                "E_REVIEW_CELL", "finding path must be a workspace-relative POSIX path"
            )
    symbol = item["symbol"]
    if symbol is not None and (
        not isinstance(symbol, str) or not symbol.strip() or len(symbol) > 256
    ):
        raise ReviewConvergenceError(
            "E_REVIEW_CELL", "finding symbol must be null or a bounded string"
        )
    priority = item["priority"]
    if isinstance(priority, bool) or (
        priority is not None
        and (not isinstance(priority, int) or priority not in {0, 1, 2, 3})
    ):
        raise ReviewConvergenceError(
            "E_REVIEW_CELL", "priority must be null or an integer from 0 through 3"
        )
    alignment = item["alignment"]
    if not isinstance(alignment, str) or alignment not in _ALIGNMENTS:
        raise ReviewConvergenceError("E_REVIEW_CELL", "objective alignment is invalid")
    canonical_key = {
        "criterion_id": criterion_id,
        "code": code.casefold(),
        "path": path.casefold() if path else "",
        "symbol": _normalized(symbol) if symbol else "",
        "title": _normalized(title),
    }
    return {
        "finding_id": _digest(canonical_key),
        **canonical_key,
        "title": title.strip(),
        "priority": priority,
        "alignment": alignment,
        "reviewer_id": reviewer_id,
        "evidence_sha256": evidence_sha256,
        "origin": "agent_proposed",
        "disposition": "reported_unresolved",
    }


def _round(
    value: object,
    contract_digest: str,
    criteria: dict[str, dict[str, Any]],
    reviewers: list[str],
):
    item = _exact(
        value,
        {"schema", "round_id", "contract_sha256", "candidate_sha256", "reviews"},
        "review round",
    )
    if item["schema"] != ROUND_SCHEMA:
        raise ReviewConvergenceError(
            "E_REVIEW_SCHEMA", "unsupported review round schema"
        )
    _identifier(item["round_id"], "round_id")
    if _hash(item["contract_sha256"], "contract_sha256") != contract_digest:
        raise ReviewConvergenceError(
            "E_REVIEW_CONTRACT_DRIFT", "review round contract digest does not match"
        )
    candidate = _hash(item["candidate_sha256"], "candidate_sha256")
    reviews = item["reviews"]
    if not isinstance(reviews, list) or len(reviews) > MAX_REVIEWERS:
        raise ReviewConvergenceError(
            "E_REVIEW_LIMIT", f"reviews must contain at most {MAX_REVIEWERS} entries"
        )
    seen_reviewers: set[str] = set()
    cells: dict[tuple[str, str], dict[str, Any]] = {}
    invalid: dict[tuple[str, str], str] = {}
    findings: list[dict[str, Any]] = []
    total_findings = 0
    for review in reviews:
        if not isinstance(review, dict) or set(review) != {
            "reviewer_id",
            "evidence_sha256",
            "criteria",
        }:
            raise ReviewConvergenceError(
                "E_REVIEW_SCHEMA", "review record has invalid fields"
            )
        reviewer_id = _identifier(review["reviewer_id"], "reviewer_id")
        evidence = _hash(review["evidence_sha256"], "review evidence_sha256")
        if reviewer_id not in reviewers or reviewer_id in seen_reviewers:
            raise ReviewConvergenceError(
                "E_REVIEW_SCHEMA", "reviewer is unknown or duplicated"
            )
        seen_reviewers.add(reviewer_id)
        responses = review["criteria"]
        if not isinstance(responses, list) or len(responses) > MAX_CRITERIA:
            invalid[(reviewer_id, "*")] = "criteria_container_invalid"
            continue
        local_seen: set[str] = set()
        for response in responses:
            if not isinstance(response, dict) or set(response) != {
                "criterion_id",
                "outcome",
                "findings",
            }:
                invalid[(reviewer_id, "*")] = "criterion_record_invalid"
                continue
            criterion_id = _identifier(response["criterion_id"], "criterion_id")
            if criterion_id not in criteria:
                raise ReviewConvergenceError(
                    "E_REVIEW_SCHEMA", "review references unknown criterion"
                )
            cell = (reviewer_id, criterion_id)
            if criterion_id in local_seen:
                invalid[cell] = "duplicate_criterion_cell"
                cells.pop(cell, None)
                continue
            local_seen.add(criterion_id)
            outcome, raw_findings = response["outcome"], response["findings"]
            if (
                not isinstance(outcome, str)
                or outcome not in {"supported", "finding", "unknown"}
                or not isinstance(raw_findings, list)
            ):
                invalid[cell] = "criterion_outcome_invalid"
                continue
            if len(raw_findings) > MAX_FINDINGS:
                invalid[cell] = "finding_limit_exceeded"
                continue
            try:
                parsed = [
                    _finding(raw, criterion_id, reviewer_id, evidence)
                    for raw in raw_findings
                ]
            except ReviewConvergenceError:
                invalid[cell] = "finding_malformed"
                continue
            if (outcome == "finding") != bool(parsed) or (
                outcome != "finding" and parsed
            ):
                invalid[cell] = "outcome_finding_mismatch"
                continue
            if outcome == "unknown":
                invalid[cell] = "reviewer_uncertain"
                cells[cell] = {"outcome": outcome, "state": "indeterminate"}
                continue
            cells[cell] = {"outcome": outcome, "state": "complete"}
            findings.extend(parsed)
            total_findings += len(parsed)
            if total_findings > MAX_FINDINGS:
                raise ReviewConvergenceError(
                    "E_REVIEW_LIMIT", f"round exceeds {MAX_FINDINGS} findings"
                )
    expected = {
        (reviewer, criterion) for reviewer in reviewers for criterion in criteria
    }
    for cell in expected:
        if cell not in cells and cell not in invalid:
            invalid[cell] = "missing_criterion_cell"
    for reviewer_id in reviewers:
        if reviewer_id not in seen_reviewers:
            for criterion_id in criteria:
                invalid[(reviewer_id, criterion_id)] = "missing_reviewer"
    coverage = [
        {
            "reviewer_id": reviewer,
            "criterion_id": criterion,
            "state": "indeterminate"
            if (reviewer, criterion) in invalid
            else cells[(reviewer, criterion)]["state"],
            "reason": invalid.get((reviewer, criterion)),
        }
        for reviewer in reviewers
        for criterion in criteria
    ]
    return item["round_id"], candidate, coverage, findings


def _consolidate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for finding in findings:
        key = finding["finding_id"]
        existing = merged.get(key)
        if existing is None:
            existing = {
                k: finding[k]
                for k in (
                    "finding_id",
                    "criterion_id",
                    "obligation_id",
                    "code",
                    "path",
                    "symbol",
                    "title",
                    "alignment",
                    "priority",
                    "origin",
                    "disposition",
                )
                if k in finding
            }
            existing["reviewers"] = []
            existing["evidence_sha256s"] = []
            merged[key] = existing
        existing["reviewers"].append(finding["reviewer_id"])
        existing["evidence_sha256s"].append(finding["evidence_sha256"])
        if finding["alignment"] != existing["alignment"]:
            existing["alignment"] = "unknown"
        priorities = [
            value
            for value in (existing["priority"], finding["priority"])
            if value is not None
        ]
        existing["priority"] = min(priorities) if priorities else None
    for value in merged.values():
        value["reviewers"] = sorted(set(value["reviewers"]))
        value["evidence_sha256s"] = sorted(set(value["evidence_sha256s"]))
        value["queue"] = (
            "human_review"
            if value["alignment"]
            in {"required_by_objective", "contradicts_objective", "unknown"}
            else "advisory_note"
        )
    return sorted(
        merged.values(),
        key=lambda value: (
            value["queue"] != "human_review",
            value["priority"] is None,
            value["priority"] or 0,
            value["finding_id"],
        ),
    )


def _verify_previous(value: object) -> dict[str, Any]:
    receipt_fields = {
        "schema",
        "round_id",
        "round_transport",
        "state",
        "contract_sha256",
        "intent_sha256",
        "contract_origin_declared",
        "candidate_sha256",
        "inputs",
        "required_reviewers",
        "criterion_ids",
        "coverage",
        "incomplete_cells",
        "findings",
        "review_delta",
        "history",
        "a2a_message",
        "provenance_unverified",
        "authority",
        "claim_boundary",
        "action_summary",
        "receipt_sha256",
    }
    if (
        not isinstance(value, dict)
        or value.get("schema") != RECEIPT_SCHEMA
        or set(value) != receipt_fields
    ):
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt schema is invalid"
        )
    copied = dict(value)
    claimed = copied.pop("receipt_sha256", None)
    if not isinstance(claimed, str) or claimed != _digest(copied):
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt self-hash does not verify"
        )
    if (
        not isinstance(value.get("findings"), list)
        or not isinstance(value.get("history"), dict)
        or set(value["history"]) != {"seen_ids", "no_longer_reported_ids"}
    ):
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt is incomplete"
        )
    coverage = value.get("coverage")
    if (
        not isinstance(coverage, list)
        or len(coverage) > MAX_REVIEWERS * MAX_CRITERIA
        or any(
            not isinstance(cell, dict) or not isinstance(cell.get("state"), str)
            for cell in coverage
        )
        or not isinstance(value.get("review_delta"), dict)
        or not isinstance(value.get("required_reviewers"), list)
        or len(value["findings"]) > MAX_FINDINGS
    ):
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt summary fields are malformed"
        )
    for key in ("seen_ids", "no_longer_reported_ids"):
        values = value["history"][key]
        if not isinstance(values, list) or any(
            not isinstance(item, str) or not _HASH.fullmatch(item) for item in values
        ):
            raise ReviewConvergenceError(
                "E_REVIEW_PRIOR_INVALID", "prior receipt history is malformed"
            )
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("finding_id"), str)
        or not _HASH.fullmatch(item["finding_id"])
        for item in value["findings"]
    ):
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt findings are malformed"
        )
    transport = value["round_transport"]
    if (
        not isinstance(transport, dict)
        or set(transport)
        != {
            "kind",
            "a2a_message_id",
            "context_id",
            "task_id",
        }
        and set(transport)
        != {
            "kind",
            "protocol_version",
            "a2a_message_id",
            "context_id",
            "task_id",
            "role_declared",
            "sender_identity_verified",
        }
    ):
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt A2A transport is malformed"
        )
    if not isinstance(transport["kind"], str) or transport["kind"] not in {
        "local_json",
        "a2a_message",
    }:
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt A2A transport kind is invalid"
        )
    for key in ("a2a_message_id", "context_id", "task_id"):
        item = transport[key]
        if item is not None and (
            not isinstance(item, str) or not item.strip() or len(item) > 256
        ):
            raise ReviewConvergenceError(
                "E_REVIEW_PRIOR_INVALID", "prior receipt A2A correlation is malformed"
            )
    if transport["kind"] == "a2a_message":
        if (
            transport.get("protocol_version") != A2A_VERSION
            or transport.get("role_declared") != "ROLE_AGENT"
            or transport.get("sender_identity_verified") is not False
            or not isinstance(transport.get("a2a_message_id"), str)
        ):
            raise ReviewConvergenceError(
                "E_REVIEW_PRIOR_INVALID", "prior receipt A2A provenance is malformed"
            )
    elif any(
        transport[key] is not None
        for key in ("a2a_message_id", "context_id", "task_id")
    ):
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "local review receipt contains A2A correlation"
        )
    authority = {
        "execution": False,
        "approval": False,
        "merge": False,
        "publication": False,
        "deployment": False,
        "signing": False,
        "policy_change": False,
    }
    if value.get("authority") != authority:
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt authority boundary is invalid"
        )

    message = value["a2a_message"]
    allowed_message_fields = {"messageId", "role", "parts", "contextId", "taskId"}
    if (
        not isinstance(message, dict)
        or set(message) - allowed_message_fields
        or not {"messageId", "role", "parts"}.issubset(message)
        or message["role"] != "ROLE_USER"
        or not isinstance(message["messageId"], str)
        or not isinstance(message["parts"], list)
        or len(message["parts"]) != 1
    ):
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt A2A handoff is malformed"
        )
    for key in ("contextId", "taskId"):
        if (
            message.get(key)
            != transport["context_id" if key == "contextId" else "task_id"]
        ):
            raise ReviewConvergenceError(
                "E_REVIEW_PRIOR_INVALID", "prior receipt A2A correlation does not match"
            )
    part = message["parts"][0]
    if (
        not isinstance(part, dict)
        or set(part) != {"data", "mediaType"}
        or part["mediaType"] != A2A_OUTPUT_MEDIA_TYPE
        or not isinstance(part["data"], dict)
    ):
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt A2A DataPart is malformed"
        )
    handoff = part["data"]
    handoff_fields = {
        "schema",
        "a2a_version",
        "round_id",
        "reply_to",
        "review_state",
        "bindings",
        "reviewers",
        "coverage",
        "findings",
        "review_delta",
        "next_action",
        "expected_reply",
        "authority",
        "claim_boundary",
        "payload_sha256",
    }
    if set(handoff) != handoff_fields or handoff["schema"] != A2A_HANDOFF_SCHEMA:
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt A2A handoff schema is invalid"
        )
    handoff_copy = dict(handoff)
    handoff_digest = handoff_copy.pop("payload_sha256")
    if not isinstance(handoff_digest, str) or handoff_digest != _digest(handoff_copy):
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt A2A handoff hash does not verify"
        )
    reply_to = handoff.get("reply_to")
    if reply_to != {
        "message_id": transport["a2a_message_id"],
        "context_id": transport["context_id"],
        "task_id": transport["task_id"],
    }:
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID",
            "prior receipt A2A reply correlation does not verify",
        )
    receipt_core = dict(value)
    receipt_core.pop("receipt_sha256")
    receipt_core.pop("a2a_message")
    bindings = handoff.get("bindings")
    if (
        not isinstance(bindings, dict)
        or set(bindings)
        != {
            "intent_sha256",
            "contract_sha256",
            "candidate_sha256",
            "receipt_core_sha256",
        }
        or bindings.get("contract_sha256") != value["contract_sha256"]
        or bindings.get("candidate_sha256") != value["candidate_sha256"]
        or bindings.get("intent_sha256") != value["intent_sha256"]
        or bindings.get("receipt_core_sha256") != _digest(receipt_core)
    ):
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt A2A bindings do not verify"
        )
    if (
        handoff.get("a2a_version") != A2A_VERSION
        or handoff.get("round_id") != value["round_id"]
        or handoff.get("reviewers") != value["required_reviewers"]
        or handoff.get("coverage") != value["coverage"]
        or handoff.get("findings") != value["findings"]
        or handoff.get("review_delta") != value["review_delta"]
        or handoff.get("next_action") != value["action_summary"]
        or handoff.get("authority") != authority
        or not isinstance(handoff.get("expected_reply"), dict)
        or handoff["expected_reply"].get("schema") != A2A_SUBMISSION_SCHEMA
    ):
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt A2A handoff facts do not match"
        )
    message_identity = {
        "payload_sha256": handoff_digest,
        "context_id": transport["context_id"],
        "task_id": transport["task_id"],
    }
    expected_message_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"urn:code-factory:a2a-review:{_digest(message_identity)}",
        )
    )
    if message["messageId"] != expected_message_id:
        raise ReviewConvergenceError(
            "E_REVIEW_PRIOR_INVALID", "prior receipt A2A messageId does not verify"
        )
    return value


def read_convergence_receipt(
    root: Path, receipt_path: str, *, include_a2a_message: bool = False
) -> dict[str, Any]:
    """Return a bounded read-only receipt summary and optional A2A message."""
    workspace = Path(root).resolve()
    receipt, relative = _read_json(workspace, receipt_path)
    verified = _verify_previous(receipt)
    findings = verified["findings"]
    coverage = verified["coverage"]
    summary = {
        "schema": RECEIPT_SCHEMA,
        "path": relative,
        "round_id": verified["round_id"],
        "state": verified["state"],
        "contract_sha256": verified["contract_sha256"],
        "candidate_sha256": verified["candidate_sha256"],
        "receipt_sha256": verified["receipt_sha256"],
        "coverage": {
            "complete_cells": sum(item.get("state") == "complete" for item in coverage),
            "incomplete_cells": sum(
                item.get("state") != "complete" for item in coverage
            ),
            "required_cells": len(coverage),
        },
        "findings": {
            "total": len(findings),
            "human_review": sum(
                item.get("queue") == "human_review" for item in findings
            ),
            "advisory": sum(item.get("queue") == "advisory_note" for item in findings),
            "items": findings[:10],
            "truncated": len(findings) > 10,
        },
        "review_delta": verified["review_delta"],
        "round_transport": verified["round_transport"],
        "a2a_handoff": {
            "available": True,
            "protocol_version": A2A_VERSION,
            "message_id": verified["a2a_message"]["messageId"],
            "context_id": verified["round_transport"]["context_id"],
            "task_id": verified["round_transport"]["task_id"],
            "media_type": A2A_OUTPUT_MEDIA_TYPE,
            "reply_schema": A2A_SUBMISSION_SCHEMA,
        },
        "provenance_unverified": True,
        "authority": dict(verified["authority"]),
        "action_summary": verified["action_summary"],
        "claim_boundary": verified["claim_boundary"],
    }
    if include_a2a_message:
        message = verified["a2a_message"]
        if len(_canonical(message)) > 48_000:
            raise ReviewConvergenceError(
                "E_REVIEW_A2A_SIZE",
                "A2A message exceeds the 48 KiB MCP export limit; use the local receipt file",
            )
        summary["a2a_message"] = message
    return summary


def review_convergence_projection(root: Path) -> dict[str, Any]:
    """Project the conventional latest receipt for local Graph Ops/WebMCP reads."""
    path = Path(".factory/review-convergence/latest.json")
    if not (Path(root) / path).is_file():
        return {
            "state": "MISSING",
            "receipt_count": 0,
            "invalid_count": 0,
            "latest": None,
            "authority": {
                "execution": False,
                "approval": False,
                "merge": False,
                "publication": False,
                "deployment": False,
                "signing": False,
                "policy_change": False,
            },
        }
    try:
        latest = read_convergence_receipt(Path(root), path.as_posix())
    except ReviewConvergenceError as exc:
        return {
            "state": "INVALID",
            "receipt_count": 1,
            "invalid_count": 1,
            "latest": {"path": path.as_posix(), "error_code": exc.code},
            "authority": {
                "execution": False,
                "approval": False,
                "merge": False,
                "publication": False,
                "deployment": False,
                "signing": False,
                "policy_change": False,
            },
        }
    return {
        "state": latest["state"],
        "receipt_count": 1,
        "invalid_count": 0,
        "latest": {
            key: latest[key]
            for key in (
                "path",
                "round_id",
                "state",
                "contract_sha256",
                "candidate_sha256",
                "receipt_sha256",
                "coverage",
                "findings",
                "review_delta",
                "a2a_handoff",
            )
        },
        "authority": latest["authority"],
        "claim_boundary": latest["claim_boundary"],
    }


def append_review_convergence(
    state: dict[str, Any], root: Path, node_writer
) -> dict[str, Any]:
    """Project the conventional convergence receipt as advisory A2A handoff facts."""
    projection = review_convergence_projection(root)
    latest = projection.get("latest")
    if isinstance(latest, dict) and isinstance(latest.get("receipt_sha256"), str):
        digest = latest["receipt_sha256"]
        node_writer(
            state,
            node_id=f"review-convergence:{digest[:24]}",
            kind="review_convergence",
            label=f"Review convergence {latest.get('state', 'unknown')}",
            source=str(latest.get("path") or ".factory/review-convergence/latest.json"),
            status=str(latest.get("state", "invalid")).lower(),
            facts={
                "receipt_sha256": digest,
                "contract_sha256": latest.get("contract_sha256"),
                "candidate_sha256": latest.get("candidate_sha256"),
                "coverage": latest.get("coverage"),
                "findings": latest.get("findings"),
                "review_delta": latest.get("review_delta"),
                "a2a_handoff": latest.get("a2a_handoff"),
                "authority": projection["authority"],
                "a2a_export_ready": projection.get("invalid_count", 0) == 0,
            },
        )
    return projection


def _round_delta(
    previous: dict[str, Any] | None,
    contract_digest: str,
    candidate: str,
    findings: list[dict[str, Any]],
    complete: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    current_ids = {item["finding_id"] for item in findings}
    if previous is None:
        return {
            "state": "no_baseline",
            "added": sorted(current_ids),
            "persistent": [],
            "no_longer_reported": [],
            "reopened": [],
        }, {"seen_ids": sorted(current_ids), "no_longer_reported_ids": []}
    if previous["contract_sha256"] != contract_digest:
        raise ReviewConvergenceError(
            "E_REVIEW_CONTRACT_DRIFT",
            "prior receipt uses a different review contract; comparison rejected",
        )
    if not complete:
        return {
            "state": "indeterminate",
            "candidate_sha256": candidate,
            "observed_ids": sorted(current_ids),
        }, previous["history"]
    old_ids = {item["finding_id"] for item in previous["findings"]}
    history = previous["history"]
    ever_seen = set(history.get("seen_ids", [])) | old_ids
    old_missing = set(history.get("no_longer_reported_ids", []))
    delta = {
        "state": "compared",
        "added": sorted(current_ids - ever_seen),
        "persistent": sorted(current_ids & old_ids),
        "no_longer_reported": sorted(old_ids - current_ids),
        "reopened": sorted(current_ids & old_missing),
    }
    now_missing = (old_missing | (old_ids - current_ids)) - current_ids
    return delta, {
        "seen_ids": sorted(ever_seen | current_ids),
        "no_longer_reported_ids": sorted(now_missing),
    }


def evaluate_review_round(
    root: Path,
    contract_path: str,
    round_path: str,
    out_path: str,
    *,
    previous_path: str | None = None,
) -> dict[str, Any]:
    """Reconcile one bounded review round into an advisory, self-hashed receipt."""
    root = Path(root).resolve()
    contract, contract_rel = _read_json(root, contract_path)
    round_value, round_rel = _read_json(root, round_path)
    round_value, round_transport = _normalize_round(round_value)
    contract, contract_digest, criteria, reviewers = _contract(contract)
    round_id, candidate, coverage, raw_findings = _round(
        round_value, contract_digest, criteria, reviewers
    )
    aligned_findings = []
    for item in raw_findings:
        criterion = criteria[item["criterion_id"]]
        aligned_findings.append(
            {
                **item,
                "obligation_id": criterion["obligation_id"],
                "criterion_origin": criterion["origin"],
            }
        )
    findings = _consolidate(aligned_findings)
    incomplete = [item for item in coverage if item["state"] != "complete"]
    previous = None
    previous_rel = None
    if previous_path is not None:
        previous, previous_rel = _read_json(root, previous_path)
        previous = _verify_previous(previous)
    target = _workspace_file(root, out_path, exists=False)
    input_paths = {
        _workspace_file(root, contract_path, exists=True),
        _workspace_file(root, round_path, exists=True),
    }
    if previous_path is not None:
        input_paths.add(_workspace_file(root, previous_path, exists=True))
    if target in input_paths:
        raise ReviewConvergenceError(
            "E_REVIEW_PATH",
            "receipt output must not overwrite a contract, review round, or prior receipt",
        )
    delta, history = _round_delta(
        previous, contract_digest, candidate, findings, not incomplete
    )
    state = (
        "INDETERMINATE"
        if incomplete
        else "REVIEW_FINDINGS"
        if findings
        else "REVIEW_COMPLETE_ADVISORY"
    )
    core = {
        "schema": RECEIPT_SCHEMA,
        "round_id": round_id,
        "round_transport": round_transport,
        "state": state,
        "contract_sha256": contract_digest,
        "intent_sha256": contract["intent_sha256"],
        "contract_origin_declared": contract["origin"],
        "candidate_sha256": candidate,
        "inputs": {
            "contract": contract_rel,
            "round": round_rel,
            "previous": previous_rel,
        },
        "required_reviewers": reviewers,
        "criterion_ids": sorted(criteria),
        "coverage": coverage,
        "incomplete_cells": incomplete,
        "findings": findings,
        "review_delta": delta,
        "history": history,
        "provenance_unverified": True,
        "authority": {
            "execution": False,
            "approval": False,
            "merge": False,
            "publication": False,
            "deployment": False,
            "signing": False,
            "policy_change": False,
        },
        "claim_boundary": "Structured reviewer submissions are caller-declared advisory input. This receipt proves bounded schema processing and source digests, not reviewer identity, independence, semantic truth, code correctness, or release readiness.",
        "action_summary": (
            "Supply or repair the listed review cells; no review completion claim is available."
            if incomplete
            else "Review findings are consolidated for human triage; no release decision was made."
            if findings
            else "All declared review cells were supplied with no reported findings; this is advisory only, not proof of code correctness."
        ),
    }
    handoff_payload = {
        "schema": A2A_HANDOFF_SCHEMA,
        "a2a_version": A2A_VERSION,
        "round_id": round_id,
        "reply_to": {
            "message_id": round_transport["a2a_message_id"],
            "context_id": round_transport["context_id"],
            "task_id": round_transport["task_id"],
        },
        "review_state": (
            "review_incomplete"
            if incomplete
            else "human_review_required"
            if any(item["queue"] == "human_review" for item in findings)
            else "review_submitted_advisory"
        ),
        "bindings": {
            "intent_sha256": contract["intent_sha256"],
            "contract_sha256": contract_digest,
            "candidate_sha256": candidate,
            "receipt_core_sha256": _digest(core),
        },
        "reviewers": reviewers,
        "coverage": coverage,
        "findings": findings,
        "review_delta": delta,
        "next_action": core["action_summary"],
        "expected_reply": {
            "schema": A2A_SUBMISSION_SCHEMA,
            "contract_sha256": contract_digest,
            "candidate_sha256": candidate,
            "round_id": round_id,
            "review": {
                "reviewer_id": "one reviewer_id listed above",
                "evidence_sha256": "sha256 of the review evidence bytes",
                "criteria": [
                    {
                        "criterion_id": criterion_id,
                        "outcome": "supported | finding | unknown",
                        "findings": [],
                    }
                    for criterion_id in sorted(criteria)
                ],
            },
        },
        "authority": dict(core["authority"]),
        "claim_boundary": "A2A transport message containing caller-declared review data; no reviewer identity, independent verification, code correctness, approval, or release status is authenticated.",
    }
    handoff_payload["payload_sha256"] = _digest(handoff_payload)
    message_identity = {
        "payload_sha256": handoff_payload["payload_sha256"],
        "context_id": round_transport["context_id"],
        "task_id": round_transport["task_id"],
    }
    a2a_message = {
        "messageId": str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"urn:code-factory:a2a-review:{_digest(message_identity)}",
            )
        ),
        "role": "ROLE_USER",
        "parts": [{"data": handoff_payload, "mediaType": A2A_OUTPUT_MEDIA_TYPE}],
    }
    if round_transport["context_id"] is not None:
        a2a_message["contextId"] = round_transport["context_id"]
    if round_transport["task_id"] is not None:
        a2a_message["taskId"] = round_transport["task_id"]
    core["a2a_message"] = a2a_message
    result = {**core, "receipt_sha256": _digest(core)}
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(_canonical(result) + b"\n")
        temporary.replace(target)
    except OSError as exc:
        raise ReviewConvergenceError(
            "E_REVIEW_WRITE", "could not atomically write receipt"
        ) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    result["path"] = target.relative_to(root).as_posix()
    return result
