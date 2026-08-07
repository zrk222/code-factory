"""Habituation gate — calibrate the human approval signal instead of trusting it.

Every other gate in this package receipts an outcome: a check passed, a proof
was recorded, a conflict was found. None of them receipt the *reliability of the
signal that produced the outcome*. The most important such signal is a human
clicking approve, and recent evidence is that this signal decays specifically
for machine-authored change.

Reviewers habituate: within the same reviewer, approval of agent-authored code
rises while inline commenting falls and review latency grows. The effect is
driven by exposure rather than by the difficulty of the change. A gate that
degrades quietly is worse than no gate, because the receipt it produces still
looks authoritative.

This module measures that decay and receipts it.

WHAT IS MEASURED AND WHAT IS NOT
--------------------------------
``scrutiny_ratio`` (review seconds per 100 changed lines) and comment density
are **measured**: they come from real review events supplied by the caller.

``drift`` is measured too, but only against a reviewer's *own* human-authored
baseline. There is no cross-reviewer comparison and no population norm, because
habituation is an exposure effect and ranking individuals against each other
would misattribute a systemic property to a person.

The link from low scrutiny to escaped defects is **modeled at best** and is
withheld by default. Correlating the two is not evidence that one caused the
other, and this module will not emit that claim without an explicit opt-in and
a stated minimum sample. It never asserts that a particular reviewer would have
caught a particular defect; that is an unfalsifiable counterfactual and it is
not something a receipt should contain.

SCRUTINY TIME IS A PROXY
------------------------
Seconds per line is not care. A fast expert is not a habituated reviewer. That
is exactly why ``blind_spot_sample`` exists and why it is designed to run before
the blocking intervention rather than after: the metric needs an external
correction term before anything is allowed to block a merge on it.
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

REVIEW_SCHEMA = "factory.habituation.review.v1"
CALIBRATION_SCHEMA = "factory.habituation.calibration.v1"
PUBLIC_SCHEMA = "factory.habituation.report.public.v1"
SAMPLE_SCHEMA = "factory.habituation.blind-sample.v1"

REVIEW_ID = re.compile(r"^[a-z\d][a-z\d._/-]*$")
MAX_REVIEW_ID_LENGTH = 120
MAX_REVIEWS = 50_000

AUTHOR_KINDS = ("agent", "human")

#: Drift thresholds, as a fraction of the reviewer's own baseline scrutiny.
WARN_DRIFT = 0.35
BLOCK_DRIFT = 0.60

#: Minimum agent-authored reviews before drift is reported at all. Below this a
#: ratio is noise, and a noisy number in a receipt is worse than no number.
MIN_AGENT_REVIEWS = 5
MIN_BASELINE_REVIEWS = 5

#: Escaped-defect linkage stays withheld below this many linked outcomes.
MIN_DEFECT_SAMPLE = 20

#: Share of low-scrutiny approvals routed to independent re-review.
BLIND_SAMPLE_RATE = 10


class HabituationError(ValueError):
    """A typed invalid review event, window, or calibration input."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _exact(value: Any) -> Any:
    """Lift floats to Decimal through str so 0.1 is exactly 0.1."""
    return Decimal(str(value)) if isinstance(value, float) else value


def _plain(value: Any) -> Any:
    """Return a JSON-native number, converting Decimal back to float."""
    return float(value) if isinstance(value, Decimal) else value


def _ratio(numerator: Any, denominator: Any) -> float | None:
    """Divide exactly, returning None rather than raising on a zero divisor."""
    if denominator is None or denominator <= 0:
        return None
    return float(_exact(numerator) / _exact(denominator))


def _identity_key(identity: str) -> str:
    """Stable pseudonym for a reviewer.

    Receipts are shareable artifacts. A reviewer identity is employment data, so
    what lands on disk is a digest, not a name. The caller keeps the mapping; the
    factory never needs it.
    """
    return hashlib.sha256(identity.strip().lower().encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Review events
# ---------------------------------------------------------------------------
def normalize_review(event: dict[str, Any]) -> dict[str, Any]:
    """Validate one review event, raising HabituationError when unusable.

    Refuses zero changed lines and non-positive durations rather than coercing
    them: a review of nothing has no scrutiny ratio, and inventing one would
    poison every window it lands in.
    """
    if not isinstance(event, dict):
        raise HabituationError("REVIEW_INVALID", "review event must be an object")

    review_id = event.get("review_id")
    if (
        not isinstance(review_id, str)
        or len(review_id) > MAX_REVIEW_ID_LENGTH
        or not REVIEW_ID.fullmatch(review_id)
    ):
        raise HabituationError("REVIEW_ID_INVALID", "review_id must match [a-z0-9][a-z0-9._/-]{0,119}")

    reviewer = event.get("reviewer")
    if not isinstance(reviewer, str) or not reviewer.strip():
        raise HabituationError("REVIEWER_REQUIRED", "review event needs a reviewer identity")

    author_kind = event.get("author_kind")
    if author_kind not in AUTHOR_KINDS:
        raise HabituationError(
            "AUTHOR_KIND_INVALID", f"author_kind must be one of {', '.join(AUTHOR_KINDS)}"
        )

    changed_lines = event.get("changed_lines")
    if not isinstance(changed_lines, int) or isinstance(changed_lines, bool) or changed_lines <= 0:
        raise HabituationError("CHANGED_LINES_INVALID", "changed_lines must be a positive integer")

    seconds = event.get("review_seconds")
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds <= 0:
        raise HabituationError("REVIEW_SECONDS_INVALID", "review_seconds must be a positive number")

    comments = event.get("inline_comments", 0)
    if not isinstance(comments, int) or isinstance(comments, bool) or comments < 0:
        raise HabituationError("COMMENTS_INVALID", "inline_comments must be a non-negative integer")

    approved = event.get("approved")
    if not isinstance(approved, bool):
        raise HabituationError("APPROVED_INVALID", "approved must be a boolean")

    return {
        "review_id": review_id,
        "reviewer_key": _identity_key(reviewer),
        "author_kind": author_kind,
        "changed_lines": changed_lines,
        "review_seconds": _plain(_exact(seconds)),
        "inline_comments": comments,
        "approved": approved,
        "scrutiny_ratio": _plain(_exact(seconds) / _exact(changed_lines) * _exact(100)),
        "comment_density": _plain(_exact(comments) / _exact(changed_lines) * _exact(100)),
        "observed_at": event.get("observed_at") or datetime.now(timezone.utc).isoformat(),
    }


def _habituation_dir(root: Path, *, create: bool = True) -> Path:
    directory = Path(root).resolve() / ".factory" / "habituation"
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    return directory


def record_review(root: Path, event: dict[str, Any], *, replace: bool = False) -> dict[str, Any]:
    """Record one review event atomically, raising HabituationError if invalid.

    Refuses to overwrite an existing event without an explicit replace: a review
    observation is evidence, and silently rewriting evidence is the failure this
    package exists to prevent.
    """
    normalized = normalize_review(event)
    safe = re.sub(r"[^a-z0-9._-]", "-", normalized["review_id"])
    destination = _habituation_dir(root) / f"review.{safe}.json"
    if destination.exists() and not replace:
        raise HabituationError("REVIEW_OVERWRITE_REFUSED", "review already recorded; pass replace explicitly")
    receipt = {"schema": REVIEW_SCHEMA, "marker": "REVIEW_OBSERVED", **normalized}
    _atomic_json(destination, receipt)
    receipt["receipt"] = str(destination)
    return receipt


def load_reviews(root: Path) -> list[dict[str, Any]]:
    """Load at most 50000 valid review receipts, skipping unreadable files.

    A single corrupt file must not block calibration over all the others.
    """
    rows: list[dict[str, Any]] = []
    for path in sorted(_habituation_dir(root, create=False).glob("review.*.json"))[:MAX_REVIEWS]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("schema") == REVIEW_SCHEMA:
            rows.append(value)
    return rows


# ---------------------------------------------------------------------------
# Calibration — drift against the reviewer's OWN baseline, never against peers
# ---------------------------------------------------------------------------
def _mean(values: list[Any]) -> Any:
    if not values:
        return None
    return _plain(sum((_exact(v) for v in values), start=_exact(0)) / _exact(len(values)))


def calibrate_reviewer(reviews: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Compute one reviewer's scrutiny drift on agent code versus their own baseline.

    Returns a withheld result rather than a number when either sample is too
    small. A drift figure computed from three reviews is noise wearing the
    costume of a measurement.
    """
    rows = list(reviews)
    agent = [r for r in rows if r["author_kind"] == "agent"]
    human = [r for r in rows if r["author_kind"] == "human"]

    agent_scrutiny = _mean([r["scrutiny_ratio"] for r in agent])
    baseline_scrutiny = _mean([r["scrutiny_ratio"] for r in human])

    withheld_reason = None
    if len(agent) < MIN_AGENT_REVIEWS:
        withheld_reason = (
            f"Only {len(agent)} agent-authored reviews observed; "
            f"{MIN_AGENT_REVIEWS} are required before drift is reported."
        )
    elif len(human) < MIN_BASELINE_REVIEWS:
        withheld_reason = (
            f"Only {len(human)} human-authored reviews observed; a reviewer's own "
            f"baseline needs {MIN_BASELINE_REVIEWS}. Without it there is nothing to "
            "compare against, and comparing against other reviewers would attribute "
            "an exposure effect to a person."
        )

    drift = None
    if withheld_reason is None and baseline_scrutiny:
        # Positive drift == less time spent per line on agent code than on human code.
        drift = _plain(
            (_exact(baseline_scrutiny) - _exact(agent_scrutiny)) / _exact(baseline_scrutiny)
        )

    band = "unknown"
    if drift is not None:
        band = "block" if drift >= BLOCK_DRIFT else "warn" if drift >= WARN_DRIFT else "nominal"

    return {
        "reviewer_key": rows[0]["reviewer_key"] if rows else None,
        "agent_reviews": len(agent),
        "baseline_reviews": len(human),
        "agent_scrutiny_ratio": agent_scrutiny,
        "baseline_scrutiny_ratio": baseline_scrutiny,
        "agent_comment_density": _mean([r["comment_density"] for r in agent]),
        "baseline_comment_density": _mean([r["comment_density"] for r in human]),
        "agent_approval_rate": _ratio(sum(1 for r in agent if r["approved"]), len(agent)),
        "baseline_approval_rate": _ratio(sum(1 for r in human if r["approved"]), len(human)),
        "scrutiny_drift": drift,
        "drift_band": band,
        "measurement": "measured",
        "withheld": drift is None,
        "withheld_reason": withheld_reason,
    }


def record_calibration(root: Path, *, replace: bool = True) -> dict[str, Any]:
    """Calibrate every observed reviewer and write one atomic receipt.

    Raises HabituationError when no review events exist. Silence would be
    indistinguishable from a clean result, and those are different states.
    """
    rows = load_reviews(root)
    if not rows:
        raise HabituationError("NO_REVIEWS", "no review events recorded; nothing to calibrate")

    by_reviewer: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_reviewer.setdefault(row["reviewer_key"], []).append(row)

    calibrations = [calibrate_reviewer(v) for _, v in sorted(by_reviewer.items())]
    bands = [c["drift_band"] for c in calibrations]

    markers = ["CALIBRATION_RECEIPTED", "BASELINE_IS_SELF_NOT_PEER"]
    if any(c["withheld"] for c in calibrations):
        markers.append("DRIFT_WITHHELD_SAMPLE_TOO_SMALL")
    if "block" in bands:
        markers.append("SCRUTINY_FLOOR_BREACHED")
    elif "warn" in bands:
        markers.append("SCRUTINY_DRIFT_WARNING")
    else:
        markers.append("SCRUTINY_NOMINAL")

    receipt = {
        "schema": CALIBRATION_SCHEMA,
        "marker": "HABITUATION_CALIBRATION_RECEIPTED",
        "markers": markers,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "reviews_observed": len(rows),
        "reviewers": len(calibrations),
        "thresholds": {"warn_drift": WARN_DRIFT, "block_drift": BLOCK_DRIFT},
        "calibrations": calibrations,
    }
    destination = _habituation_dir(root) / "calibration.json"
    if destination.exists() and not replace:
        raise HabituationError("CALIBRATION_OVERWRITE_REFUSED", "calibration exists; pass replace explicitly")
    _atomic_json(destination, receipt)
    receipt["receipt"] = str(destination)
    return receipt


# ---------------------------------------------------------------------------
# Blind-spot sampling — ships BEFORE the blocking intervention, deliberately
# ---------------------------------------------------------------------------
def blind_spot_sample(
    root: Path,
    *,
    rate: int = BLIND_SAMPLE_RATE,
    replace: bool = True,
) -> dict[str, Any]:
    """Select approved low-scrutiny reviews for independent re-review.

    Raises HabituationError on a rate outside 1-100. Selection is a deterministic
    function of the review id, so the same corpus always yields the same sample
    and an auditor can reproduce it without trusting this process.

    This exists because scrutiny time is a proxy. Without an external correction
    term the drift metric only ever confirms itself, and blocking a merge on a
    self-confirming proxy is not a gate, it is a superstition.
    """
    if not isinstance(rate, int) or isinstance(rate, bool) or not 1 <= rate <= 100:
        raise HabituationError("SAMPLE_RATE_INVALID", "rate must be an integer between 1 and 100")

    rows = [r for r in load_reviews(root) if r["author_kind"] == "agent" and r["approved"]]
    if not rows:
        raise HabituationError("NO_APPROVED_AGENT_REVIEWS", "nothing approved to re-review")

    ordered = sorted(rows, key=lambda r: r["scrutiny_ratio"])
    cutoff = max(1, len(ordered) * 50 // 100)
    low_scrutiny = ordered[:cutoff]

    selected = [
        r for r in low_scrutiny
        if int(hashlib.sha256(r["review_id"].encode("utf-8")).hexdigest()[:8], 16) % 100 < rate
    ]

    receipt = {
        "schema": SAMPLE_SCHEMA,
        "marker": "BLIND_SPOT_SAMPLE_RECEIPTED",
        "markers": ["DETERMINISTIC_SELECTION", "REPRODUCIBLE_WITHOUT_TRUSTING_THIS_PROCESS"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "rate_pct": rate,
        "eligible_low_scrutiny": len(low_scrutiny),
        "selected": [r["review_id"] for r in selected],
        "selected_count": len(selected),
        "instruction": (
            "Re-review these independently, then record the outcome with "
            "record_resample_outcome. Until outcomes exist, drift remains an "
            "uncorrected proxy and must not block a merge."
        ),
    }
    destination = _habituation_dir(root) / "blind-sample.json"
    if destination.exists() and not replace:
        raise HabituationError("SAMPLE_OVERWRITE_REFUSED", "sample exists; pass replace explicitly")
    _atomic_json(destination, receipt)
    receipt["receipt"] = str(destination)
    return receipt


def record_resample_outcome(
    root: Path,
    review_id: str,
    *,
    defect_found: bool,
    reviewer: str,
    notes: str = "",
) -> dict[str, Any]:
    """Record what an independent re-review found, raising HabituationError if unusable.

    The re-reviewer must not be the original approver. This reuses the identity
    rule the learning loop already enforces between worker and validator: a
    signal cannot correct itself.
    """
    reviews = {r["review_id"]: r for r in load_reviews(root)}
    original = reviews.get(review_id)
    if original is None:
        raise HabituationError("REVIEW_UNKNOWN", f"no recorded review {review_id}")
    if not reviewer.strip():
        raise HabituationError("REVIEWER_REQUIRED", "a re-review needs a named reviewer")
    if _identity_key(reviewer) == original["reviewer_key"]:
        raise HabituationError(
            "RESAMPLE_IDENTITY_CONFLICT",
            "the re-reviewer must differ from the original approver",
        )

    receipt = {
        "schema": "factory.habituation.resample.v1",
        "marker": "RESAMPLE_OUTCOME_RECEIPTED",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "review_id": review_id,
        "resampled_by_key": _identity_key(reviewer),
        "defect_found": bool(defect_found),
        "original_scrutiny_ratio": original["scrutiny_ratio"],
        "notes": notes.strip() or None,
    }
    safe = re.sub(r"[^a-z0-9._-]", "-", review_id)
    _atomic_json(_habituation_dir(root) / f"resample.{safe}.json", receipt)
    return receipt


def load_resamples(root: Path) -> list[dict[str, Any]]:
    """Load re-review outcome receipts, skipping unreadable files."""
    rows: list[dict[str, Any]] = []
    for path in sorted(_habituation_dir(root, create=False).glob("resample.*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("schema") == "factory.habituation.resample.v1":
            rows.append(value)
    return rows


# ---------------------------------------------------------------------------
# Escaped-defect linkage — modeled, withheld by default, never individual blame
# ---------------------------------------------------------------------------
def defect_linkage(root: Path, *, enable: bool = False) -> dict[str, Any]:
    """Relate low scrutiny to defects found on re-review. Withheld unless opted in.

    This is the most tempting number in the module and the least defensible. It
    is a correlation over a small, non-random-by-construction sample, and it is
    reported as ``modeled`` with its assumptions printed, or not at all.

    It reports rates across the sampled population. It never attributes a defect
    to a reviewer, and it never claims a particular person would have caught a
    particular bug: that counterfactual cannot be tested and does not belong in
    a receipt.
    """
    resamples = load_resamples(root)
    assumptions = [
        "Re-reviewed changes were selected from the low-scrutiny half, so the sample is not representative of all approvals.",
        "Defect discovery depends on the re-reviewer's own thoroughness, which is itself unmeasured.",
        "Correlation between scrutiny time and defects is not evidence that low scrutiny caused them.",
        "Scrutiny time is a proxy for attention; a fast expert reviewer is indistinguishable here from a habituated one.",
    ]

    if not enable:
        return {
            "tier": "modeled",
            "withheld": True,
            "withheld_reason": (
                "Defect linkage is disabled by default. It is a modeled correlation over a "
                "deliberately non-representative sample and is easy to misread as causal. "
                "Enable it explicitly once you have accepted that reading."
            ),
            "assumptions": assumptions,
            "sample_size": len(resamples),
        }

    if len(resamples) < MIN_DEFECT_SAMPLE:
        return {
            "tier": "modeled",
            "withheld": True,
            "withheld_reason": (
                f"Only {len(resamples)} re-review outcomes recorded; {MIN_DEFECT_SAMPLE} are "
                "required. A rate over a smaller sample would move by tens of points on a "
                "single additional observation."
            ),
            "assumptions": assumptions,
            "sample_size": len(resamples),
        }

    defects = sum(1 for r in resamples if r["defect_found"])
    return {
        "tier": "modeled",
        "withheld": False,
        "withheld_reason": None,
        "assumptions": assumptions,
        "sample_size": len(resamples),
        "defects_found": defects,
        "defect_rate_in_low_scrutiny_sample": _ratio(defects, len(resamples)),
        "interpretation_limit": (
            "This is the defect rate within a deliberately low-scrutiny sample. It is not "
            "the repository's defect rate and it is not attributable to any individual."
        ),
    }


# ---------------------------------------------------------------------------
# Intervention decision — the only place a merge can be blocked
# ---------------------------------------------------------------------------
def evaluate_gate(root: Path, *, allow_block: bool = False) -> dict[str, Any]:
    """Decide the intervention for the current calibration state.

    Raises HabituationError when no reviews exist. Blocking requires BOTH a
    breached scrutiny floor AND ``allow_block``, which itself requires that
    blind-spot resample outcomes exist. An uncorrected proxy is never permitted
    to stop a merge, however bad it looks.
    """
    calibration = record_calibration(root)
    resamples = load_resamples(root)
    bands = [c["drift_band"] for c in calibration["calibrations"]]

    breached = [c for c in calibration["calibrations"] if c["drift_band"] == "block"]
    warned = [c for c in calibration["calibrations"] if c["drift_band"] == "warn"]

    corrected = bool(resamples)
    action = "none"
    blocking = False
    reason = "Scrutiny is within nominal range of each reviewer's own baseline."

    if warned and not breached:
        action = "surface"
        reason = (
            f"{len(warned)} reviewer(s) show scrutiny drift above {WARN_DRIFT:.0%} of their own "
            "baseline. Surface the comparison at review time."
        )
    elif breached:
        action = "second_approver"
        reason = (
            f"{len(breached)} reviewer(s) breached the scrutiny floor of {BLOCK_DRIFT:.0%}. "
            "Require a second independent approver whose identity differs from the first."
        )
        if allow_block and corrected:
            action = "fail_closed"
            blocking = True
            reason += " Blind-spot outcomes exist, so the floor may block."
        elif allow_block and not corrected:
            reason += (
                " Blocking was requested but is refused: no blind-spot re-review outcomes "
                "exist, so the drift metric is still an uncorrected proxy. Run the sample first."
            )

    markers = ["GATE_EVALUATED", f"ACTION_{action.upper()}"]
    markers.append("PROXY_CORRECTED" if corrected else "PROXY_UNCORRECTED")
    if blocking:
        markers.append("FAIL_CLOSED_ENGAGED")

    return {
        "schema": "factory.habituation.gate.v1",
        "marker": "HABITUATION_GATE_EVALUATED",
        "markers": markers,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "blocking": blocking,
        "reason": reason,
        "proxy_corrected_by_resampling": corrected,
        "resample_outcomes": len(resamples),
        "reviewers_warned": len(warned),
        "reviewers_breached": len(breached),
        "thresholds": calibration["thresholds"],
    }


# ---------------------------------------------------------------------------
# Aggregate-safe public report
# ---------------------------------------------------------------------------
def public_habituation_report(root: Path, *, enable_defect_linkage: bool = False) -> dict[str, Any]:
    """Aggregate calibration without exporting identities, keys, or review ids.

    Deliberately carries no per-reviewer row, not even pseudonymous. Habituation
    is an exposure effect; a per-person scoreboard would misattribute a systemic
    property to individuals, and it is the shape of artifact that gets a tool
    banned rather than adopted.
    """
    rows = load_reviews(root)
    agent = [r for r in rows if r["author_kind"] == "agent"]
    human = [r for r in rows if r["author_kind"] == "human"]

    bands: dict[str, int] = {}
    drifts: list[float] = []
    if rows:
        by_reviewer: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            by_reviewer.setdefault(row["reviewer_key"], []).append(row)
        for _, group in sorted(by_reviewer.items()):
            calibration = calibrate_reviewer(group)
            bands[calibration["drift_band"]] = bands.get(calibration["drift_band"], 0) + 1
            if calibration["scrutiny_drift"] is not None:
                drifts.append(calibration["scrutiny_drift"])

    return {
        "schema": PUBLIC_SCHEMA,
        "marker": "HABITUATION_PUBLIC_REPORT",
        "markers": [
            "AGGREGATE_ONLY",
            "NO_REVIEWER_IDENTITIES_EXPORTED",
            "NO_PER_REVIEWER_ROWS_EXPORTED",
            "NO_REVIEW_IDENTIFIERS_EXPORTED",
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "reviews_observed": len(rows),
        "agent_authored_reviews": len(agent),
        "human_authored_reviews": len(human),
        "reviewers_observed": len({r["reviewer_key"] for r in rows}),
        "mean_agent_scrutiny_ratio": _mean([r["scrutiny_ratio"] for r in agent]),
        "mean_baseline_scrutiny_ratio": _mean([r["scrutiny_ratio"] for r in human]),
        "agent_approval_rate": _ratio(sum(1 for r in agent if r["approved"]), len(agent)),
        "baseline_approval_rate": _ratio(sum(1 for r in human if r["approved"]), len(human)),
        "reviewers_by_drift_band": dict(sorted(bands.items())),
        "median_scrutiny_drift": (
            sorted(drifts)[len(drifts) // 2] if drifts else None
        ),
        "drift_measurement": "measured",
        "defect_linkage": defect_linkage(root, enable=enable_defect_linkage),
    }


def export_public_habituation_report(root: Path, destination: Path, *, enable_defect_linkage: bool = False) -> Path:
    """Write the aggregate-safe public report to disk for publication."""
    target = Path(destination)
    _atomic_json(target, public_habituation_report(root, enable_defect_linkage=enable_defect_linkage))
    return target
