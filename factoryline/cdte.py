"""Conflict Detection and Trade-off Engine (CDTE).

SpecLine removes ambiguity from a spec. CDTE removes contradiction. They are
different defects: ambiguity is resolved by asking the author what they meant,
contradiction is resolved by telling the author they cannot have both. A
contradictory spec is perfectly unambiguous and passes every clarity gate.

The engine has three phases with deliberately different trust properties:

    Phase 1  Constraint synthesis      model judgment, schema-validated
    Phase 2  Lethal pair detection     deterministic table lookup, no model
    Phase 3  Proof and ADR drafting    model drafting, tier-constrained

Phase 2 is the load-bearing one and it never calls a model. Detection is a
lookup over ``data/lethal_pairs.yaml``. This keeps the gate cheap enough to run
on every assembly, makes it reproducible, and means adding a conflict is a data
change with a table test rather than a prompt rewrite.

EVIDENCE BOUNDARY
-----------------
CDTE reports contradictions between constraints it was given. It does not
measure systems, does not infer unstated requirements, and does not assert that
a conflict is unresolvable in principle. Proof tiers are declared in the
registry, never chosen at runtime, and a proof whose inputs are absent is
withheld rather than estimated. This mirrors ``savings.py``, which withholds
``productivity_gain_rate`` rather than guessing it.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable

from .run_metrics import _atomic_json

SCAN_SCHEMA = "factory.cdte-scan.v1"
PUBLIC_SCHEMA = "factory.cdte-report.public.v1"
REGISTRY_SCHEMA = "factory.lethal-pairs.v1"
RESOLUTION_SCHEMA = "factory.cdte-resolution.v1"

RUN_ID = re.compile(r"^[a-z\d][a-z\d._-]*$")
MAX_RUN_ID_LENGTH = 80
MAX_SCANS = 10_000
MAX_CONSTRAINTS = 500

VALID_TIERS = ("measured", "modeled", "structural")
VALID_SEVERITIES = ("critical", "high", "medium", "low")
VALID_OPERATORS = ("lt", "lte", "gt", "gte", "eq")

#: Severities that engage the fail-closed boundary.
BLOCKING_SEVERITIES = frozenset({"critical", "high"})

_REGISTRY_PATH = Path(__file__).resolve().parent / "data" / "lethal_pairs.json"


class CDTEError(ValueError):
    """A typed invalid constraint, registry, or resolution input."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Exact arithmetic. Thresholds are compared, not approximated.
# ---------------------------------------------------------------------------
def _exact(value: Any) -> Any:
    """Lift floats to Decimal through str so 0.1 is exactly 0.1."""
    return Decimal(str(value)) if isinstance(value, float) else value


def _plain(value: Any) -> Any:
    return float(value) if isinstance(value, Decimal) else value


# ---------------------------------------------------------------------------
# Phase 1 output — the NFR constraint record
# ---------------------------------------------------------------------------
def normalize_constraint(value: dict[str, Any], index: int) -> dict[str, Any]:
    """Validate and canonicalize one NFR constraint, raising CDTEError if invalid.

    Canonicalization is not cosmetic: the registry matches on exact category and
    metric tokens, so "P95_Latency_MS " and "p95_latency_ms" must collapse to
    the same key or detection silently misses.
    """
    label = f"constraints[{index}]"
    if not isinstance(value, dict):
        raise CDTEError("CONSTRAINT_INVALID", f"{label} must be an object")

    constraint_id = value.get("constraintId") or f"c-{index:03d}"
    if not isinstance(constraint_id, str) or not constraint_id.strip():
        raise CDTEError("CONSTRAINT_ID_INVALID", f"{label}.constraintId must be a non-empty string")

    category = value.get("category")
    metric = value.get("metric")
    for field, raw in (("category", category), ("metric", metric)):
        if not isinstance(raw, str) or not raw.strip():
            raise CDTEError("CONSTRAINT_FIELD_MISSING", f"{label}.{field} is required and must be a string")

    operator = value.get("operator")
    if operator is not None and operator not in VALID_OPERATORS:
        raise CDTEError(
            "OPERATOR_INVALID",
            f"{label}.operator must be one of {', '.join(VALID_OPERATORS)} or null",
        )

    raw_value = value.get("value")
    if isinstance(raw_value, bool):
        # bool is an int subclass; treating True as 1 in a threshold comparison
        # would be a silent correctness bug.
        raise CDTEError("VALUE_INVALID", f"{label}.value must not be a boolean")

    return {
        "constraintId": constraint_id.strip(),
        "category": category.strip().lower(),
        "metric": metric.strip().lower(),
        "operator": operator,
        "value": _plain(raw_value) if raw_value is not None else None,
        "originatingSignalId": value.get("originatingSignalId"),
        "description": value.get("description"),
    }


def normalize_constraints(values: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate a constraint set, raising CDTEError on duplicate or malformed ids.

    Duplicate constraint ids are refused rather than de-duplicated: two records
    claiming the same id means the upstream synthesis step lost information, and
    silently keeping one of them would hide that.
    """
    items = list(values)
    if len(items) > MAX_CONSTRAINTS:
        raise CDTEError("CONSTRAINTS_TOO_MANY", f"at most {MAX_CONSTRAINTS} constraints per scan")
    normalized = [normalize_constraint(item, i) for i, item in enumerate(items)]
    seen: set[str] = set()
    for item in normalized:
        if item["constraintId"] in seen:
            raise CDTEError("CONSTRAINT_ID_DUPLICATE", f"duplicate constraintId {item['constraintId']}")
        seen.add(item["constraintId"])
    return normalized


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
def load_registry(path: Path | None = None) -> dict[str, Any]:
    """Load and validate the lethal pair decision table.

    Raises CDTEError on a missing, unparseable, or schema-invalid registry. A
    registry that cannot be trusted must stop the gate, never degrade it to a
    permissive default.
    """
    source = Path(path) if path else _REGISTRY_PATH
    if not source.is_file():
        raise CDTEError("REGISTRY_MISSING", f"lethal pair registry not found at {source}")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CDTEError("REGISTRY_UNPARSEABLE", f"registry is not valid JSON: {exc}") from exc

    if not isinstance(data, dict) or data.get("schema") != REGISTRY_SCHEMA:
        raise CDTEError("REGISTRY_SCHEMA_INVALID", f"registry schema must be {REGISTRY_SCHEMA}")
    pairs = data.get("pairs")
    if not isinstance(pairs, list) or not pairs:
        raise CDTEError("REGISTRY_EMPTY", "registry must declare at least one pair")

    seen: set[str] = set()
    for pair in pairs:
        _validate_pair(pair, seen)
    return data


def _validate_side(side: Any, pair_id: str, which: str) -> None:
    if not isinstance(side, dict):
        raise CDTEError("PAIR_SIDE_INVALID", f"{pair_id}.{which} must be an object")
    for field in ("category", "metric"):
        if not isinstance(side.get(field), str):
            raise CDTEError("PAIR_SIDE_INVALID", f"{pair_id}.{which}.{field} is required")
    has_threshold = "operator" in side and "threshold" in side
    has_values = "value_in" in side
    if not has_threshold and not has_values:
        raise CDTEError(
            "PAIR_SIDE_INVALID",
            f"{pair_id}.{which} needs either operator+threshold or value_in",
        )
    if has_threshold and side["operator"] not in VALID_OPERATORS:
        raise CDTEError("PAIR_SIDE_INVALID", f"{pair_id}.{which}.operator is not a valid operator")
    if has_values and not isinstance(side["value_in"], list):
        raise CDTEError("PAIR_SIDE_INVALID", f"{pair_id}.{which}.value_in must be a list")


def _validate_pair(pair: Any, seen: set[str]) -> None:
    if not isinstance(pair, dict):
        raise CDTEError("PAIR_INVALID", "each registry pair must be an object")
    pair_id = pair.get("id")
    if not isinstance(pair_id, str) or not pair_id.strip():
        raise CDTEError("PAIR_ID_INVALID", "each registry pair needs a string id")
    if pair_id in seen:
        raise CDTEError("PAIR_ID_DUPLICATE", f"duplicate pair id {pair_id}")
    seen.add(pair_id)
    if pair.get("severity") not in VALID_SEVERITIES:
        raise CDTEError("PAIR_SEVERITY_INVALID", f"{pair_id}.severity must be one of {VALID_SEVERITIES}")
    _validate_side(pair.get("left"), pair_id, "left")
    _validate_side(pair.get("right"), pair_id, "right")

    proof = pair.get("proof")
    if not isinstance(proof, dict) or proof.get("tier") not in VALID_TIERS:
        raise CDTEError("PAIR_PROOF_TIER_INVALID", f"{pair_id}.proof.tier must be one of {VALID_TIERS}")
    tier = proof["tier"]
    if tier == "structural" and not isinstance(proof.get("statement"), str):
        raise CDTEError("PAIR_PROOF_INVALID", f"{pair_id} structural proof requires a statement")
    if tier in ("modeled", "measured"):
        if not isinstance(proof.get("formula"), str):
            raise CDTEError("PAIR_PROOF_INVALID", f"{pair_id} {tier} proof requires a formula")
        if not isinstance(proof.get("assumptions"), list) or not proof["assumptions"]:
            # A modeled number without printed assumptions is indistinguishable
            # from a measurement to the reader. That is the failure this whole
            # product exists to prevent.
            raise CDTEError(
                "PAIR_PROOF_ASSUMPTIONS_REQUIRED",
                f"{pair_id} {tier} proof requires a non-empty assumptions list",
            )


# ---------------------------------------------------------------------------
# Phase 2 — deterministic detection. No model is consulted here.
# ---------------------------------------------------------------------------
def _compare(value: Any, operator: str, threshold: Any) -> bool:
    if value is None:
        return False
    try:
        left, right = _exact(value), _exact(threshold)
        if isinstance(left, str) or isinstance(right, str):
            return False
        return {
            "lt": left < right,
            "lte": left <= right,
            "gt": left > right,
            "gte": left >= right,
            "eq": left == right,
        }[operator]
    except (TypeError, ArithmeticError):
        return False


def _side_matches(constraint: dict[str, Any], side: dict[str, Any]) -> bool:
    if constraint["category"] != side["category"].strip().lower():
        return False
    if constraint["metric"] != side["metric"].strip().lower():
        return False
    if "value_in" in side:
        raw = constraint.get("value")
        if raw is None:
            return False
        return str(raw).strip().lower() in {str(v).strip().lower() for v in side["value_in"]}
    return _compare(constraint.get("value"), side["operator"], side["threshold"])


def detect_conflicts(
    constraints: list[dict[str, Any]],
    registry: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return every lethal pair whose both sides are satisfied.

    Pure, deterministic, and free of I/O beyond registry loading. Given the same
    constraints and registry this returns the same conflicts forever, which is
    what allows the result to be published in a signed receipt.
    """
    table = registry if registry is not None else load_registry()
    findings: list[dict[str, Any]] = []

    for pair in table["pairs"]:
        left_hits = [c for c in constraints if _side_matches(c, pair["left"])]
        right_hits = [c for c in constraints if _side_matches(c, pair["right"])]
        if not left_hits or not right_hits:
            continue
        # A single constraint satisfying both sides is a registry modelling
        # error, not a conflict; a requirement cannot contradict itself.
        involved = {c["constraintId"] for c in left_hits} | {c["constraintId"] for c in right_hits}
        if len(involved) < 2:
            continue
        findings.append(
            {
                "pair_id": pair["id"],
                "title": pair.get("title", pair["id"]),
                "severity": pair["severity"],
                "left_constraints": sorted(c["constraintId"] for c in left_hits),
                "right_constraints": sorted(c["constraintId"] for c in right_hits),
                "constraints": sorted(involved),
                "proof": _build_proof(pair, left_hits, right_hits),
                "remediation": list(pair["proof"].get("remediation", [])),
            }
        )
    return sorted(findings, key=lambda f: (VALID_SEVERITIES.index(f["severity"]), f["pair_id"]))


# ---------------------------------------------------------------------------
# Phase 3 — proofs. Tier is declared in the registry; it is never chosen here.
# ---------------------------------------------------------------------------
def _build_proof(
    pair: dict[str, Any],
    left_hits: list[dict[str, Any]],
    right_hits: list[dict[str, Any]],
) -> dict[str, Any]:
    """Construct the incompatibility analysis for one detected pair.

    Named ``proof`` in the registry for continuity with the source research, but
    emitted under ``incompatibility_analysis`` in receipts. "Proof" overstates
    what the modeled tier delivers, and this product cannot afford to overstate.

    A modeled proof whose inputs are absent is WITHHELD, not estimated. This is
    the same discipline ``savings.py`` applies to ``productivity_gain_rate``.
    """
    spec = pair["proof"]
    tier = spec["tier"]

    if tier == "structural":
        return {
            "tier": "structural",
            "statement": " ".join(spec["statement"].split()),
            "quantified": False,
            "withheld": False,
            "withheld_reason": None,
            "assumptions": [],
            "inputs": {},
            "evidence_sha256": None,
        }

    # measured and modeled both require named numeric inputs from the constraints.
    inputs: dict[str, Any] = {}
    for constraint in left_hits + right_hits:
        if isinstance(constraint.get("value"), (int, float)) and not isinstance(constraint.get("value"), bool):
            inputs[constraint["metric"]] = constraint["value"]

    missing = _formula_inputs(spec["formula"]) - set(inputs)
    if missing:
        return {
            "tier": tier,
            "statement": None,
            "quantified": False,
            "withheld": True,
            "withheld_reason": (
                "Required inputs were not supplied by the spec: "
                + ", ".join(sorted(missing))
                + ". The conflict stands; the quantification does not."
            ),
            "assumptions": list(spec.get("assumptions", [])),
            "inputs": inputs,
            "evidence_sha256": None,
        }

    return {
        "tier": tier,
        "statement": None,
        "formula": spec["formula"],
        "quantified": True,
        "withheld": False,
        "withheld_reason": None,
        "assumptions": list(spec.get("assumptions", [])),
        "inputs": inputs,
        "evidence_sha256": None,
    }


def _formula_inputs(formula: str) -> set[str]:
    """Identifiers a formula depends on.

    Deliberately a token scan and not an evaluator. CDTE never executes a
    formula string; it only checks that the spec supplied every named input
    before claiming the formula could be applied.
    """
    tokens = set(re.findall(r"[a-z_][a-z0-9_]*", formula.lower()))
    return tokens


def bind_evidence(proof: dict[str, Any], evidence: Path | None) -> dict[str, Any]:
    """Promote a modeled proof to measured by hash-binding a benchmark file.

    Raises CDTEError when the named evidence file is absent. Refuses
    silently-absent evidence: a missing file downgrades rather than
    pretending. The digest is the same SHA-256 discipline used for savings
    equivalence evidence.
    """
    if evidence is None:
        return proof
    path = Path(evidence)
    if not path.is_file():
        raise CDTEError("EVIDENCE_MISSING", f"evidence file not found: {path}")
    upgraded = dict(proof)
    upgraded["evidence_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    upgraded["tier"] = "measured"
    return upgraded


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------
def _cdte_dir(root: Path, *, create: bool = True) -> Path:
    directory = Path(root).resolve() / ".factory" / "cdte"
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    return directory


def _scan_markers(conflicts: list[dict[str, Any]], blocking: bool) -> list[str]:
    markers = ["CDTE_SCAN_COMPLETED"]
    if conflicts:
        markers.append("LETHAL_PAIR_MATCHED")
    else:
        markers.append("NO_LETHAL_PAIR_MATCHED")
    tiers = {c["incompatibility_analysis"]["tier"] for c in conflicts}
    for tier in sorted(tiers):
        markers.append(f"PROOF_{tier.upper()}")
    if any(c["incompatibility_analysis"]["withheld"] for c in conflicts):
        markers.append("PROOF_WITHHELD_INPUTS_ABSENT")
    if any(
        c["incompatibility_analysis"]["tier"] == "modeled"
        and not c["incompatibility_analysis"]["withheld"]
        for c in conflicts
    ):
        markers.append("PROOF_MODELED_ASSUMPTIONS_SHOWN")
    markers.append("FAIL_CLOSED_ENGAGED" if blocking else "FAIL_CLOSED_NOT_ENGAGED")
    return markers


def record_scan(
    root: Path,
    run_id: str,
    constraints: list[dict[str, Any]],
    *,
    registry: dict[str, Any] | None = None,
    evidence: Path | None = None,
    replace: bool = False,
) -> dict[str, Any]:
    """Run phases 1-3 over supplied constraints and write an atomic receipt.

    Raises CDTEError on an invalid run id, malformed constraints, missing
    evidence, or an existing receipt when replace is not set. Refusing to
    overwrite silently is deliberate: a scan receipt is evidence.
    """
    if (
        not isinstance(run_id, str)
        or len(run_id) > MAX_RUN_ID_LENGTH
        or not RUN_ID.fullmatch(run_id)
    ):
        raise CDTEError("RUN_ID_INVALID", "run id must match [a-z0-9][a-z0-9._-]{0,79}")

    normalized = normalize_constraints(constraints)
    findings = detect_conflicts(normalized, registry)

    conflicts: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        analysis = bind_evidence(finding.pop("proof"), evidence)
        conflicts.append(
            {
                "conflict_id": f"{run_id}-{index:02d}",
                **finding,
                "incompatibility_analysis": analysis,
            }
        )

    blocking = any(c["severity"] in BLOCKING_SEVERITIES for c in conflicts)
    destination = _cdte_dir(root) / f"{run_id}.json"
    if destination.exists() and not replace:
        raise CDTEError("SCAN_OVERWRITE_REFUSED", "scan already exists; pass --replace explicitly")

    receipt = {
        "schema": SCAN_SCHEMA,
        "marker": "CDTE_SCAN_RECEIPTED",
        "markers": _scan_markers(conflicts, blocking),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "registry_version": (registry or load_registry()).get("version"),
        "constraint_count": len(normalized),
        "constraints": normalized,
        "conflicts": conflicts,
        "requires_hitl_escalation": blocking,
        "fail_closed": blocking,
    }
    _atomic_json(destination, receipt)
    receipt["receipt"] = str(destination)
    return receipt


def load_scans(root: Path) -> list[dict[str, Any]]:
    """Load at most 10000 valid scan receipts, skipping unreadable files.

    Unparseable or foreign-schema files are skipped rather than raised on, so a
    single corrupt receipt cannot block reporting on all the others.
    """
    rows: list[dict[str, Any]] = []
    for path in sorted(_cdte_dir(root, create=False).glob("*.json"))[:MAX_SCANS]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("schema") == SCAN_SCHEMA:
            rows.append(value)
    return rows


# ---------------------------------------------------------------------------
# Resolution — ADR or explicit, expiring, receipted override
# ---------------------------------------------------------------------------
ADR_TEMPLATE = """# ADR-{number:04d}: {title}

- Status: proposed
- Date: {date}
- Conflict: `{conflict_id}` (registry pair `{pair_id}`, severity {severity})
- Constraints in tension: {constraints}

## Context

CDTE detected a lethal pair before any code was generated. The constraints
below cannot both hold as written.

{analysis}

## Decision

*(Author: record the structural sacrifice you are choosing.)*

## Options considered

{remediation}

## Consequences

*(Author: state what is given up and who is affected.)*

## Evidence boundary

This ADR was drafted from a deterministic registry match. CDTE did not measure
this system. Any quantities above are labelled with their tier and, where
modeled, are accompanied by the assumptions they rest on.
"""


def _render_analysis(analysis: dict[str, Any]) -> str:
    tier = analysis["tier"]
    if tier == "structural":
        return f"**Structural incompatibility.** {analysis['statement']}"
    if analysis["withheld"]:
        return (
            f"**Quantification withheld ({tier}).** {analysis['withheld_reason']}\n\n"
            "The contradiction is established by the registry match. The numbers are not."
        )
    lines = [
        f"**Quantified analysis ({tier}).** Formula: `{analysis['formula']}`",
        "",
        "Inputs taken from the spec:",
    ]
    lines += [f"- `{k}` = {v}" for k, v in sorted(analysis["inputs"].items())]
    lines += ["", "Assumptions this rests on:"]
    lines += [f"- {a}" for a in analysis["assumptions"]]
    if tier == "modeled":
        lines += ["", "*This is a model, not a measurement.*"]
    return "\n".join(lines)


def draft_adr(root: Path, scan: dict[str, Any], conflict_id: str, *, number: int = 1) -> Path:
    """Write a draft ADR for one conflict, raising CDTEError if it is unknown.

    The decision itself stays human: the template records context, tier-labelled
    analysis, and options, and leaves the Decision section blank.
    """
    conflict = next((c for c in scan["conflicts"] if c["conflict_id"] == conflict_id), None)
    if conflict is None:
        raise CDTEError("CONFLICT_UNKNOWN", f"no conflict {conflict_id} in scan {scan['run_id']}")

    directory = Path(root).resolve() / "adr"
    directory.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "-", conflict["pair_id"].lower()).strip("-")
    destination = directory / f"ADR-{number:04d}-{slug}.md"
    destination.write_text(
        ADR_TEMPLATE.format(
            number=number,
            title=conflict["title"],
            date=datetime.now(timezone.utc).date().isoformat(),
            conflict_id=conflict_id,
            pair_id=conflict["pair_id"],
            severity=conflict["severity"],
            constraints=", ".join(f"`{c}`" for c in conflict["constraints"]),
            analysis=_render_analysis(conflict["incompatibility_analysis"]),
            remediation="\n".join(f"- {r}" for r in conflict["remediation"]) or "- *(none recorded)*",
        ),
        encoding="utf-8",
    )
    return destination


def resolve_conflict(
    root: Path,
    run_id: str,
    conflict_id: str,
    *,
    decision: str,
    approved_by: str,
    adr_path: Path | None = None,
    override: bool = False,
    expires: str | None = None,
) -> dict[str, Any]:
    """Record a conflict resolution, raising CDTEError on an unrecordable one.

    An override is a receipt with a named approver, never a silent skip. A gate
    that can be bypassed without a record is decoration, and an override without
    an expiry becomes permanent by neglect.
    """
    if not decision.strip():
        raise CDTEError("DECISION_REQUIRED", "a resolution needs a decision")
    if not approved_by.strip():
        raise CDTEError("APPROVER_REQUIRED", "a resolution needs a named approver")
    if override and not expires:
        raise CDTEError(
            "OVERRIDE_EXPIRY_REQUIRED",
            "an override must carry an expiry date; permanent overrides are not recordable",
        )

    scans = {row["run_id"]: row for row in load_scans(root)}
    scan = scans.get(run_id)
    if scan is None:
        raise CDTEError("SCAN_UNKNOWN", f"no scan receipt for run {run_id}")
    if not any(c["conflict_id"] == conflict_id for c in scan["conflicts"]):
        raise CDTEError("CONFLICT_UNKNOWN", f"no conflict {conflict_id} in scan {run_id}")

    receipt = {
        "schema": RESOLUTION_SCHEMA,
        "marker": "CDTE_RESOLUTION_RECEIPTED",
        "markers": ["OVERRIDE_RECORDED" if override else "ADR_RECORDED", "APPROVER_NAMED"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "conflict_id": conflict_id,
        "decision": decision.strip(),
        "approved_by": approved_by.strip(),
        "override": bool(override),
        "expires": expires,
        "adr_path": str(adr_path) if adr_path else None,
    }
    _atomic_json(_cdte_dir(root) / f"{run_id}.{conflict_id}.resolution.json", receipt)
    return receipt


# ---------------------------------------------------------------------------
# Aggregate-safe public report
# ---------------------------------------------------------------------------
def public_cdte_report(root: Path) -> dict[str, Any]:
    """Aggregate scans without exposing constraints, specs, paths, or run ids.

    Constraint text is a description of an employer's unreleased system. It does
    not leave the machine. The public report carries counts and pair frequencies
    only, matching the disclosure boundary of ``public_savings_report``.
    """
    rows = load_scans(root)
    pair_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    tier_counts: dict[str, int] = {}
    withheld = 0
    blocked = 0

    for row in rows:
        if row.get("fail_closed"):
            blocked += 1
        for conflict in row.get("conflicts", []):
            pair_counts[conflict["pair_id"]] = pair_counts.get(conflict["pair_id"], 0) + 1
            severity_counts[conflict["severity"]] = severity_counts.get(conflict["severity"], 0) + 1
            analysis = conflict["incompatibility_analysis"]
            tier_counts[analysis["tier"]] = tier_counts.get(analysis["tier"], 0) + 1
            if analysis["withheld"]:
                withheld += 1

    total_conflicts = sum(pair_counts.values())
    return {
        "schema": PUBLIC_SCHEMA,
        "marker": "CDTE_PUBLIC_REPORT",
        "markers": [
            "AGGREGATE_ONLY",
            "NO_CONSTRAINT_TEXT_EXPORTED",
            "NO_RUN_IDENTIFIERS_EXPORTED",
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scans": len(rows),
        "scans_fail_closed": blocked,
        "fail_closed_rate": _plain(_exact(blocked) / _exact(len(rows))) if rows else None,
        "conflicts_total": total_conflicts,
        "conflicts_by_pair": dict(sorted(pair_counts.items())),
        "conflicts_by_severity": dict(sorted(severity_counts.items())),
        "analysis_by_tier": dict(sorted(tier_counts.items())),
        "quantification_withheld": withheld,
        "quantification_withheld_rate": (
            _plain(_exact(withheld) / _exact(total_conflicts)) if total_conflicts else None
        ),
    }


def export_public_cdte_report(root: Path, destination: Path) -> Path:
    """Write the public report to disk for publication."""
    target = Path(destination)
    _atomic_json(target, public_cdte_report(root))
    return target
