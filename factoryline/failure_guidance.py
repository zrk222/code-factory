"""Consistent causal summaries for human and automated correction loops."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


_GUIDANCE: dict[str, tuple[str, str, bool]] = {
    "SOURCE_INVALID": (
        "signal capture",
        "Use one of the source values listed by `factory signal capture --help`.",
        True,
    ),
    "SOURCE_EXACTLY_ONE": (
        "target source contract",
        "Provide one prompt or one --prd path, never both or neither.",
        True,
    ),
    "TARGET_UNSUPPORTED": (
        "target capability selection",
        "Choose a target returned by factory targets or install a compatible signed target pack.",
        True,
    ),
    "TRIGGER_UNSUPPORTED": (
        "target trigger contract",
        "Choose a trigger returned by factory create --help.",
        True,
    ),
    "OUTPUT_EXISTS": (
        "target output safety",
        "Choose an empty output directory; existing source is never overwritten by target compilation.",
        True,
    ),
    "AUTHORIZATION_INVALID": (
        "signal provenance",
        "Supply the reviewed capture authorization; do not infer connector entitlement.",
        True,
    ),
    "TITLE_INVALID": (
        "signal input contract",
        "Provide a non-empty title of at most 240 characters.",
        True,
    ),
    "BODY_INVALID": (
        "signal input contract",
        "Provide non-empty UTF-8 body data within the 65,536-byte limit.",
        True,
    ),
    "SEVERITY_INVALID": (
        "signal input contract",
        "Set severity to an integer from 1 through 5.",
        True,
    ),
    "SIGNAL_QUEUE_INVALID": (
        "signal queue verification",
        "Preserve the invalid queue for diagnosis, then rebuild it from verified signal receipts.",
        False,
    ),
    "OPINION_DOCK_LINE_BUDGET": (
        "Opinion Dock verification",
        "Consolidate or retire rules until the rendered dock is at most 2,000 lines, then verify again.",
        False,
    ),
    "OWNER_MISMATCH": (
        "owner authorization",
        "Use the recorded Opinion Dock owner or obtain an explicit owner-authored correction or decision.",
        False,
    ),
    "RULE_INVALID": (
        "Opinion Dock rule contract",
        "Repair the rule fields, bounded weight, action, and match terms before retrying.",
        True,
    ),
    "RATIONALE_INVALID": (
        "owner decision contract",
        "Provide a concise non-empty rationale within the documented limit.",
        True,
    ),
    "HANDS_OFF_RULE_ENFORCED": (
        "architecture guardrail",
        "Leave the change blocked or obtain a named Product Owner override with rationale.",
        False,
    ),
    "OWNER_DECISION_REQUIRED": (
        "signal promotion",
        "Record an approved Product Owner decision before promotion.",
        False,
    ),
    "OWNER_REQUIRED": (
        "mission ownership",
        "Provide the recorded mission owner before creating or deciding the mission.",
        True,
    ),
    "DECISION_INVALID": (
        "approval decision contract",
        "Choose an allowed approve, defer, or reject decision and retry.",
        True,
    ),
    "ARTIFACT_EXISTS": (
        "atomic artifact write",
        "Reuse the identical artifact, choose a new output, or pass explicit `--force` after reviewing the replacement.",
        False,
    ),
    "ARTIFACT_INVALID": (
        "artifact parsing",
        "Repair or regenerate the malformed artifact from its verified source.",
        True,
    ),
    "SCHEMA_INVALID": (
        "artifact schema verification",
        "Regenerate the artifact with the expected schema version; do not coerce it silently.",
        True,
    ),
    "HASH_INVALID": (
        "artifact integrity verification",
        "Restore the original bound artifact or invalidate downstream receipts and regenerate them.",
        True,
    ),
    "PRODUCT_GRAPH_GAPS": (
        "Product Graph compilation",
        "Add testable requirements and at least one Gherkin acceptance scenario to the PRD.",
        False,
    ),
    "MISSION_BUDGET_INVALID": (
        "mission budget contract",
        "Lower the requested iterations, wall time, tokens, or cost to the published hard ceiling.",
        True,
    ),
    "MISSION_INPUT_DRIFT": (
        "mission input verification",
        "Restore the bound inputs or create a new mission and invalidate receipts derived from the changed files.",
        True,
    ),
    "MISSION_DECISION_OWNER_MISMATCH": (
        "mission execution approval",
        "Use the mission owner or create a separately reviewed mission with the correct owner.",
        False,
    ),
    "VALIDATION_OUTSIDE_ROOT": (
        "validation provenance",
        "Move the validation manifest beneath the mission workspace and retry.",
        True,
    ),
    "EVIDENCE_OUTSIDE_ROOT": (
        "evidence provenance",
        "Use evidence files beneath the mission workspace so hashes are locally reviewable.",
        True,
    ),
    "EVIDENCE_MISSING": (
        "completion evidence",
        "Produce the missing deterministic evidence file, then run independent verification again.",
        True,
    ),
    "VERIFIER_IDENTITY_DISTINCT": (
        "independent verification",
        "Assign a verifier identity distinct from the creator and rerun from the bounded review context.",
        False,
    ),
    "CREATOR_VERIFIER_CONTEXT_WALL": (
        "verifier context boundary",
        "Remove creator-private context and provide only the allowed mission, diff, and evidence inputs.",
        True,
    ),
    "NO_FINISH_CONTRACT": (
        "mission completion",
        "Pass every declared criterion exactly once with non-empty local evidence; do not weaken the criteria.",
        True,
    ),
    "E_INPUT": (
        "CLI input",
        "Correct the referenced path or JSON input and retry the same command.",
        True,
    ),
    "PACK_JSON_INVALID": (
        "capability pack parsing",
        "Repair the named structured pack file and rerun pack validation.",
        True,
    ),
    "PACK_VALIDATION_FAILED": (
        "capability pack verification",
        "Repair the first structural, signature, golden, canary, UX-state, or mutation failure and validate again.",
        True,
    ),
    "PACK_SIGNATURE_INVALID": (
        "capability pack trust",
        "Restore the signed bytes or obtain a new reviewed signature from a trusted pack publisher.",
        False,
    ),
    "PACK_BUILTINS_MISSING": (
        "installed package data",
        "Reinstall a complete wheel containing factoryline/builtin_packs and rerun factory pack list.",
        True,
    ),
    "PACK_EXISTS": (
        "capability pack installation",
        "Keep the installed pack or retry with explicit --force after reviewing the signed replacement.",
        False,
    ),
    "PACK_PATH_INVALID": (
        "capability pack installation boundary",
        "Use a simple pack id with no path separators or traversal components.",
        True,
    ),
    "PACK_BACKUP_EXISTS": (
        "capability pack recovery",
        "Inspect and recover the named backup before another installation attempt.",
        False,
    ),
    "PACK_INSTALL_FAILED": (
        "capability pack atomic installation",
        "Inspect the causal filesystem error; the prior install was restored when PACK_ROLLBACK_RESTORED is present.",
        False,
    ),
    "HOLLOW_PACK_VALIDATOR": (
        "capability pack mutation proof",
        "Strengthen the structural validator until every declared pack mutation is rejected.",
        False,
    ),
    "MIGRATION_READINESS_INPUT": (
        "migration readiness contract",
        "Declare every readiness lane with an argv command and local executable evidence.",
        True,
    ),
    "MIGRATION_AGENT_NOT_READY": (
        "migration readiness gate",
        "Run and attach proof for every missing or unverified readiness lane before creating a migration mission.",
        False,
    ),
    "MIGRATION_READINESS_DRIFT": (
        "migration readiness evidence",
        "Restore the bound evidence or regenerate the readiness receipt from current executable proof.",
        True,
    ),
    "MIGRATION_EVIDENCE_OUTSIDE_ROOT": (
        "migration evidence boundary",
        "Move the evidence beneath the repository root and regenerate its receipt.",
        True,
    ),
    "BROWSER_FLOW_INVALID": (
        "computer-control verification",
        "Rerun the declared browser flow with a fresh verifier until URL, click bound, assertions, and artifact hashes all pass.",
        True,
    ),
    "REPOSITORY_CONTEXT_GIT_REQUIRED": (
        "AutoWiki and Lore source",
        "Run inside a Git worktree so context can be generated from tracked files, ADRs, and commit history.",
        True,
    ),
    "FEEDBACK_INPUT_INVALID": (
        "outcome feedback contract",
        "Provide a mission id, metric, observed value, target, and local measured evidence.",
        True,
    ),
    "LEARNING_TASK_INVALID": (
        "learning task contract",
        "Provide a stable task id, recorded owner, and concrete objective.",
        True,
    ),
    "MILESTONE_CONTRACT_INVALID": (
        "milestone contract",
        "Declare ordered milestones with unique ids and one or more id-bearing criteria.",
        True,
    ),
    "MILESTONE_UNKNOWN": (
        "milestone selection",
        "Choose a milestone declared by the bound learning task.",
        True,
    ),
    "MILESTONE_ORDER_BLOCKED": (
        "milestone gate",
        "Promote valid evidence for each preceding milestone before continuing.",
        False,
    ),
    "INSTRUCTION_CANDIDATE_INVALID": (
        "instruction candidate",
        "Provide a worker identity and a bounded unique instruction list.",
        True,
    ),
    "OUTCOME_OUTSIDE_ROOT": (
        "learning provenance",
        "Move worker outcome evidence beneath the task workspace before proposing instructions.",
        True,
    ),
    "VALIDATOR_IDENTITY_DISTINCT": (
        "independent learning validation",
        "Assign a validator distinct from the worker that proposed the instruction candidate.",
        False,
    ),
    "MILESTONE_VALIDATION_INCOMPLETE": (
        "milestone validation",
        "Validate every criterion exactly once with passing, hash-bound evidence.",
        True,
    ),
    "PROMOTER_IDENTITY_DISTINCT": (
        "instruction promotion authority",
        "Use three distinct identities for worker, validator, and recorded human owner.",
        False,
    ),
    "WORKER_ID_INVALID": (
        "fresh worker packet",
        "Provide a non-empty identity for the new isolated worker.",
        True,
    ),
    "SEARCH_VARIANT_INVALID": (
        "learning search policy",
        "Choose ASHA, Hyperband, or BOHB explicitly.",
        True,
    ),
    "SEARCH_SPACE_INVALID": (
        "six-dimension search contract",
        "Declare one or more non-empty candidate lists under the published d1-d6 dimensions.",
        True,
    ),
    "SEARCH_BUDGET_INVALID": (
        "learning search budget",
        "Use positive bounded resources, concurrency, samples, grace period, and reduction factor.",
        True,
    ),
}


def explain_failure(
    code: str, reason: str, *, errors: Iterable[str] = ()
) -> dict[str, Any]:
    """Return one stable causal summary shared by humans and coding loops."""
    point, next_action, auto_correctable = _GUIDANCE.get(
        code,
        (
            "workflow verification",
            "Inspect the causal code and evidence, repair the earliest failed stage, then rerun that stage.",
            False,
        ),
    )
    evidence = [str(item) for item in errors if str(item)]
    return {
        "schema": "factory.failure_summary.v1",
        "point_of_failure": point,
        "causal_code": code,
        "why": reason,
        "evidence": evidence,
        "auto_correctable": auto_correctable,
        "next_action": next_action,
        "loop_instruction": "Repair the earliest causal failure only; preserve stronger gates and rerun the failed stage before continuing.",
    }


_CI_PREFIX = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ?|\x1b\[[0-9;]*[A-Za-z]")
_CI_KEYS = (
    ("pytest", re.compile(r"^FAILED (\S+)")),
    ("assertion", re.compile(r"^E\s+(\w*(?:Error|Exception)\b.*)")),
    ("exception", re.compile(r"^(\w+(?:Error|Exception): .*)$")),
    ("node-test", re.compile(r"^not ok \d+ - (.+)$")),
    ("format", re.compile(r"^Would reformat: (\S+)")),
    ("lint", re.compile(r"^(\S+\.\w+:\d+:\d+: [A-Z]+\d+)")),
    ("assert", re.compile(r"^(AssertionError: .*)$")),
)
_CI_VOLATILE = (
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f-]{27}\b"), "U"),
    (re.compile(r"\b[0-9a-f]{7,64}\b"), "H"),
    (re.compile(r"\d+(?:\.\d+)*"), "N"),
    (re.compile(r"\\"), "/"),
)
_CI_JOB_NOISE = re.compile(
    r"\((?:[\w.-]+, )*[\w.-]+\)|\b(?:windows|ubuntu|macos)(?:-latest)?\b|python \d[\d.]*|shard \d+/\d+",
    re.IGNORECASE,
)


def _ci_normal(text: str) -> str:
    for pattern, replacement in _CI_VOLATILE:
        text = pattern.sub(replacement, text)
    return " ".join(text.split())[:240]


def ci_failure_signature(
    log: str, workflow: str, job: str, step: str
) -> dict[str, Any]:
    """Normalise one failed CI job into a content-only signature; volatile ids, numbers and paths are folded."""
    lines = [_CI_PREFIX.sub("", line).strip() for line in log.splitlines()]
    end = next(
        (i for i, line in enumerate(lines) if line.startswith("##[error]")), len(lines)
    )
    start = max(
        (i for i in range(end) if lines[i].startswith("##[endgroup]")), default=0
    )
    lines = lines[start:end]
    keys, kind = set(), None
    for line in lines:
        for name, pattern in _CI_KEYS:
            if match := pattern.match(line):
                keys.add(_ci_normal(match.group(1)))
                kind = kind or name
                break
    if not keys:
        tail = [line for line in lines if line and not line.startswith("##[")]
        keys = {_ci_normal(line) for line in tail[-3:]}
        kind = "tail"
    identity = {
        "workflow": workflow,
        "job": " ".join(_CI_JOB_NOISE.sub("", job).split()),
        "step": _ci_normal(step),
    }
    keys = sorted(keys)[:12]
    return {
        "schema": "factory.ci-failure-signature.v1",
        **identity,
        "kind": kind,
        "keys": keys,
        "signature_sha256": _ci_sha({**identity, "keys": keys}),
        "family_sha256": _ci_sha({**identity, "kind": kind}),
    }


def _ci_sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _verified_fix_receipt(receipt: Any) -> bool:
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != "factory.fix-workflow.v1"
    ):
        return False
    core = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    from .fix_workflow import _sha

    return (
        receipt.get("mode") == "execute"
        and receipt.get("state") == "PASS"
        and receipt.get("receipt_sha256") == _sha(core)
    )


def remember_ci_repair(
    index: Path, signature: dict[str, Any], receipt: Any
) -> dict[str, Any]:
    """Append a failure signature with its executed, passing fix receipt; anything else is refused."""
    if not _verified_fix_receipt(receipt):
        raise ValueError(
            "fix receipt is not an executed, passing, self-consistent fix-workflow receipt"
        )
    entry = {
        "signature_sha256": signature["signature_sha256"],
        "family_sha256": signature["family_sha256"],
        "fix_receipt_sha256": receipt["receipt_sha256"],
        "fix_id": receipt.get("fix_id"),
    }
    index.parent.mkdir(parents=True, exist_ok=True)
    with index.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def triage_ci_failure(index: Path, signature: dict[str, Any]) -> dict[str, Any]:
    """Recall earlier verified repairs for this signature; the result is a lead for a human, never an action."""
    entries = []
    if index.is_file():
        for line in index.read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict):
                entries.append(entry)
    exact = [
        e for e in entries if e.get("signature_sha256") == signature["signature_sha256"]
    ]
    family = [
        e for e in entries if e.get("family_sha256") == signature["family_sha256"]
    ]
    return {
        "schema": "factory.ci-failure-triage.v1",
        "signature": signature,
        "status": "KNOWN_FAILURE" if exact else "REQUIRES_HUMAN_ATTENTION",
        "verified_repairs": exact,
        "similar_repairs": [e for e in family if e not in exact][:5],
        "authority": "none",
        "next_action": "Re-run the recalled fix workflow against this failure before applying anything."
        if exact
        else "Diagnose the failure; record the executed, passing fix receipt so the next recurrence is recalled.",
    }
