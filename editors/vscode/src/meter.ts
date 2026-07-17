import { escapeHtml } from "./receipt";

type RecordValue = Record<string, unknown>;

function asRecord(value: unknown): RecordValue {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as RecordValue : {};
}

function scalar(value: unknown): string {
  return value === undefined || value === null ? "not available" : String(value);
}

function measured(value: RecordValue, unit = ""): string {
  if (value.value === undefined || value.value === null) {
    return `unknown (${scalar(value.unknown)} unreported)`;
  }
  return `${value.value}${unit} (${scalar(value.known)} reported, ${scalar(value.unknown)} unknown)`;
}

function percent(value: unknown): string {
  return value === undefined || value === null ? "not available" : `${(Number(value) * 100).toFixed(1)}%`;
}

export function meterHtml(value: unknown): string {
  const snapshot = asRecord(value);
  const summary = asRecord(snapshot.summary);
  const activity = asRecord(snapshot.activity);
  const flow = asRecord(summary.flow);
  const queue = asRecord(flow.queue_ms);
  const agent = asRecord(flow.agent_ms);
  const tools = asRecord(flow.deterministic_tool_ms);
  const review = asRecord(flow.human_review_ms);
  const firstPass = asRecord(flow.first_pass_gate_rate);
  const retries = asRecord(flow.retry_count);
  const replay = asRecord(flow.replay_hits);
  const avoided = asRecord(flow.model_calls_avoided);
  const cost = asRecord(flow.cost_usd);
  const tokenQuality = asRecord(flow.token_quality);
  const costQuality = asRecord(flow.cost_quality);
  const latest = asRecord(activity.latest_stage);
  const rows: Array<[string, string]> = [
    ["Stages measured", scalar(summary.stages_measured)],
    ["Measured build time", summary.build_wall_ms === undefined ? "not available" : `${summary.build_wall_ms} ms`],
    ["Model calls", scalar(summary.build_model_calls)],
    ["Build tokens", summary.tokens_reported_by_modules === true ? scalar(summary.build_tokens) : "not reported by modules"],
    ["Flow efficiency", percent(flow.flow_efficiency)],
    ["Queue time", measured(queue, " ms")],
    ["Agent time", measured(agent, " ms")],
    ["Deterministic tool time", measured(tools, " ms")],
    ["Human review time", measured(review, " ms")],
    ["First-pass gate rate", percent(firstPass.value)],
    ["Retries", measured(retries)],
    ["Replays", measured(replay)],
    ["Model calls avoided", measured(avoided)],
    ["Rework ratio", percent(flow.rework_ratio)],
    ["Requirements / token", scalar(flow.requirements_per_token)],
    ["Requirements / engineering hour", scalar(flow.requirements_per_engineering_hour)],
    ["Reported cost", measured(cost, " USD")],
    ["Token quality", `exact ${scalar(tokenQuality.exact)} / estimated ${scalar(tokenQuality.estimated)} / unknown ${scalar(tokenQuality.unknown)}`],
    ["Cost quality", `exact ${scalar(costQuality.exact)} / estimated ${scalar(costQuality.estimated)} / unknown ${scalar(costQuality.unknown)}`],
    ["Escaped defects / release", scalar(flow.escaped_defects_per_release)],
    ["Rollback rate", percent(flow.rollback_rate)],
    ["Runs observed", scalar(activity.runs_observed)],
    ["Stage success rate", percent(activity.stage_success_rate)],
    ["Last measurement", scalar(snapshot.last_measurement_at)],
    ["Latest stage", Object.keys(latest).length ? `${scalar(latest.module)}:${scalar(latest.stage)} (${latest.ok === true ? "ok" : "failed"})` : "none yet"],
  ];
  const body = rows.map(([label, entry]) => `<tr><th>${escapeHtml(label)}</th><td>${escapeHtml(entry)}</td></tr>`).join("");
  const note = escapeHtml(scalar(summary.note));
  return `<!doctype html><html><body><h2>FactoryLine Meter</h2><table>${body}</table><p>${note}</p><p><small>Local receipt data only. Unknown telemetry remains unavailable rather than becoming zero.</small></p></body></html>`;
}
