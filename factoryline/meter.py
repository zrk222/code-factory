"""factoryline.meter — real, receipted cost measurement. No invented numbers.

The factory's value claim is "saves time and tokens." That claim is only credible
if the numbers are *measured on your own runs*, not marketed. This module records
what actually happened and computes the savings against an explicit, stated
baseline — so every figure in the summary table traces to a receipt.

Two things are measured per stage:
  - wall_ms      : real elapsed time (measured here, always honest)
  - model_calls / tokens : reported BY each module in its receipt's `meter` block
                   (0 if the module made no model call — which is the whole point:
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


class MeterLog:
    """Append-only meter log at <root>/.factory/meter.jsonl."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.path = self.root / LAYOUT["state"] / "meter.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, t: StageTiming) -> None:
        if not t.recorded_at:
            t.recorded_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(t.__dict__) + "\n")

    def stages(self) -> list[StageTiming]:
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
            "stages_measured": 0,
            "status": "no measured runs yet",
            "note": "Run `factory assemble <feature>` first. Savings are computed only "
                    "from real measured runs — factoryline never reports a percentage "
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
    return {
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
        "note": ("All wall_ms are measured. " + (
            "Token counts are reported by one or more modules." if tokens_reported else
            "NOTE: no module reported token usage on these runs, so the token-savings "
            "figure reflects the MODEL (compile-once → 0/run), not measured token "
            "deltas. Wire per-module token reporting for measured token savings.") +
            " Savings depend on the declared baseline above. Nothing here is fabricated."),
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
        "schema": "factory.meter.live.v1",
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
                "recorded_at": latest.recorded_at or None,
            } if latest else None),
        },
        "scope_limits": [
            "This is a local append-only log snapshot, not a machine-independent benchmark.",
            "Token totals are measured only when a module reports its standard meter block.",
        ],
    }


def summary_table(summary: dict) -> str:
    """Render the summary as a plain-text table (portable, paste-anywhere)."""
    if summary.get("stages_measured", 0) == 0:
        return ("FACTORY COST & SAVINGS\n" + "-" * 52 + "\n"
                + summary.get("status", "no data") + "\n" + summary.get("note", ""))
    a = summary["assumptions"]
    factory_model = a["factory_model"].replace("→", "->")
    note = summary["note"].replace("→", "->")
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
