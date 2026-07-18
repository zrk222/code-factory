"""factoryline.meter - real, receipted cost measurement. No invented numbers.

The factory's value claim is "saves time and tokens." That claim is only credible
if the numbers are *measured on your own runs*, not marketed. This module records
what actually happened and computes the savings against an explicit, stated
baseline - so every figure in the summary table traces to a receipt.

Two things are measured per stage:
  - wall_ms      : real elapsed time (measured here, always honest)
  - model_calls / tokens : reported BY each module in its receipt's `meter` block
                   (0 if the module made no model call - which is the whole point:
                    HSF compiles once and runs at zero token cost thereafter)

The savings model is explicit and conservative:
  baseline = "an agent re-derives context and re-generates every run"
  factory  = "compile/verify once, then run deterministically at zero token cost"
Savings are reported per the baseline you declare, and the baseline is printed in
the summary so no one can accuse the number of hiding its assumptions.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import datetime as _dt
import json
import time

from .contract import LAYOUT, Meter


@dataclass
class StageTiming:
    module: str
    stage: str
    wall_ms: int
    model_calls: int
    tokens_in: int
    tokens_out: int
    ok: bool
    usage_reported: bool = False
    recorded_at: str = ""
    feature: str = ""
    run_id: str = ""
    mission_id: str = ""
    queue_ms: int | None = None
    human_review_ms: int | None = None
    rework_lines: int | None = None
    cache_hits: int | None = None
    invalidated_stages: int | None = None
    outcome_status: str | None = None
    usage_quality: str = "unknown"
    agent_ms: int | None = None
    deterministic_tool_ms: int | None = None
    changed_lines: int | None = None
    replay_hits: int | None = None
    model_calls_avoided: int | None = None
    first_pass: bool | None = None
    retry_count: int | None = None
    requirements_accepted: int | None = None
    cost_usd: float | None = None
    token_quality: str | None = None
    cost_quality: str = "unknown"
    escaped_defects: int | None = None
    releases: int | None = None
    rollbacks: int | None = None


class MeterLog:
    """Append-only meter log at <root>/.factory/meter.jsonl."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.path = self.root / LAYOUT["state"] / "meter.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, t: StageTiming) -> None:
        """Append one measured stage timing to the newline-delimited meter ledger."""
        qualities = {"exact", "estimated", "unknown"}
        if t.usage_quality not in qualities or t.cost_quality not in qualities:
            raise ValueError("meter quality must be exact, estimated, or unknown")
        if t.token_quality is None:
            t.token_quality = t.usage_quality
        if t.token_quality not in qualities:
            raise ValueError("token quality must be exact, estimated, or unknown")
        numeric_fields = (
            "wall_ms", "model_calls", "tokens_in", "tokens_out", "queue_ms",
            "human_review_ms", "rework_lines", "cache_hits", "invalidated_stages",
            "agent_ms", "deterministic_tool_ms", "changed_lines", "replay_hits",
            "model_calls_avoided", "retry_count", "requirements_accepted", "cost_usd",
            "escaped_defects", "releases", "rollbacks",
        )
        if any((value := getattr(t, field)) is not None and value < 0 for field in numeric_fields):
            raise ValueError("meter values must be non-negative")
        if not t.recorded_at:
            t.recorded_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(t.__dict__) + "\n")

    def stages(self) -> list[StageTiming]:
        """Load all valid recorded stages while ignoring blank ledger lines."""
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text().splitlines():
            if line.strip():
                payload = json.loads(line)
                out.append(StageTiming(**payload))
        return out


class stopwatch:
    """Context manager: measures real wall time in ms. Always honest."""
    def __enter__(self):
        self._t0 = time.monotonic(); return self
    def __exit__(self, *a):
        self.wall_ms = int((time.monotonic() - self._t0) * 1000)


def summarize(root: Path, *, baseline_tokens_per_run: int = 4000,
              runs_projected: int = 1000) -> dict:
    """Aggregate the meter log into a real, assumptions-stated savings summary.

    baseline_tokens_per_run: what a *stateless agent* would spend re-deriving and
        re-generating this workflow every single run (declare your own; default is
        a deliberately conservative 4k).
    runs_projected: how many production runs you project (savings compound here).
    """
    log = MeterLog(root)
    stages = log.stages()
    total = Meter()
    for s in stages:
        total = total.merge(Meter(s.wall_ms, s.model_calls, s.tokens_in, s.tokens_out))

    # Honesty guard: with no measured stages, there is nothing to compare. Refuse
    # to print a savings percentage rather than show a misleading "100%".
    if not stages:
        return {
            "schema": "factory.meter.summary.v2",
            "markers": ["METER_V2_BACKWARD_COMPATIBLE", "FLOW_EFFICIENCY_MEASURED", "METER_UNKNOWN_VALUES_PRESERVED"],
            "stages_measured": 0,
            "status": "no measured runs yet",
            "note": "Run `factory assemble <feature>` first. Savings are computed only "
                    "from real measured runs - factoryline never reports a percentage "
                    "against zero data.",
        }

    # Factory cost is paid ONCE (compile + verify). Production runs cost 0 tokens
    # for the compiled decision path (HSF's H=0 guarantee).
    factory_one_time_tokens = total.tokens_in + total.tokens_out
    baseline_total_tokens = baseline_tokens_per_run * runs_projected
    factory_total_tokens = factory_one_time_tokens  # + 0 per run for compiled path
    tokens_saved = max(baseline_total_tokens - factory_total_tokens, 0)
    pct_saved = (tokens_saved / baseline_total_tokens * 100) if baseline_total_tokens else 0.0

    # Second honesty guard: if modules reported no token usage, say so explicitly
    # rather than implying the savings are proven. wall_ms is always real.
    tokens_reported = any(stage.usage_reported for stage in stages)
    flow = _flow_metrics(stages)
    return {
        "schema": "factory.meter.summary.v2",
        "markers": [
            "METER_V2_BACKWARD_COMPATIBLE", "FLOW_EFFICIENCY_MEASURED",
            "METER_TIME_CLASSES_SEPARATE", "METER_TOKEN_COST_QUALITY_SEPARATE",
            "METER_PRODUCTIVITY_GUARDED", "METER_QUALITY_OUTCOMES_GUARDED",
        ],
        "stages_measured": len(stages),
        "build_wall_ms": total.wall_ms,
        "build_model_calls": total.model_calls,
        "build_tokens": factory_one_time_tokens,
        "tokens_reported_by_modules": tokens_reported,
        "assumptions": {
            "baseline_tokens_per_run": baseline_tokens_per_run,
            "runs_projected": runs_projected,
            "baseline_model": "stateless agent re-derives+regenerates every run",
            "factory_model": "compile/verify once, then 0 tokens per compiled run (HSF H=0)",
        },
        "baseline_total_tokens": baseline_total_tokens,
        "factory_total_tokens": factory_total_tokens,
        "tokens_saved": tokens_saved,
        "pct_tokens_saved": round(pct_saved, 1),
        "flow": flow,
        "note": ("All wall_ms are measured. " + (
            "Token counts are reported by one or more modules." if tokens_reported else
            "NOTE: no module reported token usage on these runs, so the token-savings "
            "figure reflects the MODEL (compile-once -> 0/run), not measured token "
            "deltas. Wire per-module token reporting for measured token savings.") +
            " Savings depend on the declared baseline above. Nothing here is fabricated."),
    }


def _known_sum(stages: list[StageTiming], field: str) -> dict:
    values = [getattr(stage, field) for stage in stages]
    known = [value for value in values if value is not None]
    return {"value": sum(known) if known else None, "known": len(known), "unknown": len(values) - len(known)}


def _known_rate(stages: list[StageTiming], field: str) -> dict:
    values = [getattr(stage, field) for stage in stages]
    known = [value for value in values if value is not None]
    return {
        "value": round(sum(bool(value) for value in known) / len(known), 4) if known else None,
        "known": len(known),
        "unknown": len(values) - len(known),
    }


def _guarded_ratio(numerator: dict, denominator: dict, *, scale: float = 1.0) -> float | None:
    if numerator["unknown"] or denominator["unknown"] or numerator["value"] is None:
        return None
    if denominator["value"] in (None, 0):
        return None
    return round(numerator["value"] / denominator["value"] * scale, 4)


def _flow_metrics(stages: list[StageTiming]) -> dict:
    """Expose flow observations without silently treating missing telemetry as zero."""
    queue = _known_sum(stages, "queue_ms")
    review = _known_sum(stages, "human_review_ms")
    rework = _known_sum(stages, "rework_lines")
    cache = _known_sum(stages, "cache_hits")
    invalidated = _known_sum(stages, "invalidated_stages")
    agent = _known_sum(stages, "agent_ms")
    tools = _known_sum(stages, "deterministic_tool_ms")
    changed = _known_sum(stages, "changed_lines")
    replay = _known_sum(stages, "replay_hits")
    avoided = _known_sum(stages, "model_calls_avoided")
    retries = _known_sum(stages, "retry_count")
    requirements = _known_sum(stages, "requirements_accepted")
    costs = _known_sum(stages, "cost_usd")
    escaped = _known_sum(stages, "escaped_defects")
    releases = _known_sum(stages, "releases")
    rollbacks = _known_sum(stages, "rollbacks")
    first_pass = _known_rate(stages, "first_pass")
    classified_execution = agent["unknown"] == 0 and tools["unknown"] == 0
    legacy_execution = agent["known"] == 0 and tools["known"] == 0
    complete_flow = bool(stages) and queue["unknown"] == 0 and review["unknown"] == 0 and (classified_execution or legacy_execution)
    execution = (
        (agent["value"] or 0) + (tools["value"] or 0)
        if classified_execution else sum(stage.wall_ms for stage in stages)
    )
    total = execution + (queue["value"] or 0) + (review["value"] or 0)
    token_quality = {
        quality: sum((stage.token_quality or stage.usage_quality) == quality for stage in stages)
        for quality in ("exact", "estimated", "unknown")
    }
    cost_quality = {
        quality: sum(stage.cost_quality == quality for stage in stages)
        for quality in ("exact", "estimated", "unknown")
    }
    token_total = sum(stage.tokens_in + stage.tokens_out for stage in stages)
    requirements_per_token = None
    if requirements["unknown"] == 0 and requirements["value"] is not None and token_quality["unknown"] == 0 and token_total:
        requirements_per_token = round(requirements["value"] / token_total, 8)
    requirements_per_engineering_hour = None
    if requirements["unknown"] == 0 and requirements["value"] is not None and all(item["unknown"] == 0 for item in (agent, tools, review)):
        engineering_ms = (agent["value"] or 0) + (tools["value"] or 0) + (review["value"] or 0)
        if engineering_ms:
            requirements_per_engineering_hour = round(requirements["value"] / (engineering_ms / 3_600_000), 4)
    return {
        "execution_ms": sum(stage.wall_ms for stage in stages),
        "queue_ms": queue,
        "agent_ms": agent,
        "deterministic_tool_ms": tools,
        "human_review_ms": review,
        "review_minutes": round(review["value"] / 60000, 4) if review["unknown"] == 0 and review["value"] is not None else None,
        "rework_lines": rework,
        "changed_lines": changed,
        "rework_ratio": _guarded_ratio(rework, changed),
        "cache_hits": cache,
        "replay_hits": replay,
        "model_calls_avoided": avoided,
        "first_pass_gate_rate": first_pass,
        "retry_count": retries,
        "invalidated_stages": invalidated,
        "flow_efficiency": round(execution / total, 4) if complete_flow and total else None,
        "requirements_accepted": requirements,
        "requirements_per_token": requirements_per_token,
        "requirements_per_engineering_hour": requirements_per_engineering_hour,
        "cost_usd": costs,
        "token_quality": token_quality,
        "cost_quality": cost_quality,
        "escaped_defects": escaped,
        "releases": releases,
        "rollbacks": rollbacks,
        "escaped_defects_per_release": _guarded_ratio(escaped, releases),
        "rollback_rate": _guarded_ratio(rollbacks, releases),
        "outcomes": {
            name: sum(stage.outcome_status == name for stage in stages)
            for name in ("achieved", "not_achieved", "inconclusive")
        },
        "usage_quality": token_quality,
        "scope": "local observed workflow telemetry; unknown fields remain null",
    }


def overhead(root: Path) -> dict:
    """Measured per-gate wall-clock overhead; no benchmark baseline is invented."""
    groups: dict[tuple[str, str], list[StageTiming]] = {}
    for timing in MeterLog(root).stages():
        groups.setdefault((timing.module, timing.stage), []).append(timing)
    gates = []
    for (module, stage), rows in sorted(groups.items()):
        values = [row.wall_ms for row in rows]
        gates.append({"module": module, "stage": stage, "runs": len(rows),
                      "total_wall_ms": sum(values), "avg_wall_ms": round(sum(values) / len(values), 1),
                      "max_wall_ms": max(values), "failed_runs": sum(not row.ok for row in rows)})
    return {"schema": "factory.overhead.v1", "gates": gates,
            "total_wall_ms": sum(item["total_wall_ms"] for item in gates),
            "scope_limits": ["Wall-clock measurements are local run observations, not a machine-independent performance claim.", "No gate is skipped by this report; use project policy to decide which gates are required."]}


def live_snapshot(root: Path, *, baseline_tokens_per_run: int = 4000,
                  runs_projected: int = 1000) -> dict:
    """Return one current, local-only meter observation for dashboards or watches."""
    log = MeterLog(root)
    stages = log.stages()
    successful = sum(stage.ok for stage in stages)
    failed = len(stages) - successful
    run_ids = {stage.run_id for stage in stages if stage.run_id}
    known_features = sorted({stage.feature for stage in stages if stage.feature})
    latest = stages[-1] if stages else None
    return {
        "schema": "factory.meter.live.v2",
        "markers": [
            "METER_V2_BACKWARD_COMPATIBLE", "FLOW_EFFICIENCY_MEASURED",
            "METER_TIME_CLASSES_SEPARATE", "METER_TOKEN_COST_QUALITY_SEPARATE",
        ],
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "meter_log": str(log.path),
        "last_measurement_at": stages[-1].recorded_at if stages else None,
        "summary": summarize(
            root,
            baseline_tokens_per_run=baseline_tokens_per_run,
            runs_projected=runs_projected,
        ),
        "overhead": overhead(root),
        "activity": {
            "runs_observed": len(run_ids) if run_ids else None,
            "features_observed": known_features,
            "stages_successful": successful,
            "stages_failed": failed,
            "stage_success_rate": round(successful / len(stages), 4) if stages else None,
            "latest_stage": ({
                "module": latest.module,
                "stage": latest.stage,
                "feature": latest.feature or None,
                "run_id": latest.run_id or None,
                "ok": latest.ok,
                "wall_ms": latest.wall_ms,
                "usage_reported": latest.usage_reported,
                "usage_quality": latest.usage_quality,
                "mission_id": latest.mission_id or None,
                "recorded_at": latest.recorded_at or None,
            } if latest else None),
        },
        "scope_limits": [
            "This is a local append-only log snapshot, not a machine-independent benchmark.",
            "Token totals are measured only when a module reports its standard meter block.",
            "Queue, agent, deterministic-tool, review, cost, replay, rework, quality, and outcome values remain null when not reported.",
        ],
    }


def summary_table(summary: dict) -> str:
    """Render the summary as a plain-text table (portable, paste-anywhere)."""
    if summary.get("stages_measured", 0) == 0:
        return ("FACTORY COST & SAVINGS\n" + "-" * 52 + "\n"
                + summary.get("status", "no data") + "\n" + summary.get("note", ""))
    a = summary["assumptions"]
    factory_model = a["factory_model"]
    note = summary["note"]
    tok_line = (f"one-time build tokens  : {summary['build_tokens']:,}"
                if summary.get("tokens_reported_by_modules")
                else "one-time build tokens  : (not reported by modules on these runs)")
    lines = [
        "FACTORY COST & SAVINGS (measured on your runs)",
        "-" * 52,
        f"stages measured        : {summary['stages_measured']}",
        f"one-time build time    : {summary['build_wall_ms']} ms",
        f"one-time model calls   : {summary['build_model_calls']}",
        tok_line,
        "",
        "SAVINGS MODEL (assumptions stated)",
        "-" * 52,
        f"baseline / run         : {a['baseline_tokens_per_run']:,} tokens  ({a['baseline_model']})",
        f"runs projected         : {a['runs_projected']:,}",
        f"baseline total         : {summary['baseline_total_tokens']:,} tokens",
        f"factory total          : {summary['factory_total_tokens']:,} tokens  ({factory_model})",
        f"tokens saved (model)   : {summary['tokens_saved']:,}",
        f"percent saved (model)  : {summary['pct_tokens_saved']}%",
        "",
        note,
    ]
    return "\n".join(lines)


def live_summary_table(snapshot: dict) -> str:
    """Human-readable companion to the JSON snapshot for terminal users."""
    activity = snapshot["activity"]
    latest = activity["latest_stage"]
    lines = [summary_table(snapshot["summary"]), "", "LIVE ACTIVITY (local meter log)", "-" * 52]
    if activity["runs_observed"] is None:
        lines.append("runs observed          : unavailable for legacy entries")
    else:
        lines.append(f"runs observed          : {activity['runs_observed']}")
    lines.extend([
        f"stages successful       : {activity['stages_successful']}",
        f"stages failed           : {activity['stages_failed']}",
        "stage success rate      : " + (
            f"{activity['stage_success_rate'] * 100:.1f}%"
            if activity["stage_success_rate"] is not None else "no stages yet"
        ),
        "features observed       : " + (", ".join(activity["features_observed"]) or "none yet"),
        "latest stage            : " + (
            f"{latest['module']}:{latest['stage']} ({'ok' if latest['ok'] else 'failed'})"
            if latest else "none yet"
        ),
        f"last measurement        : {snapshot['last_measurement_at'] or 'none yet'}",
    ])
    return "\n".join(lines)
