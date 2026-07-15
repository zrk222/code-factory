import { escapeHtml } from "./receipt";

type RecordValue = Record<string, unknown>;

function asRecord(value: unknown): RecordValue {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as RecordValue : {};
}

function scalar(value: unknown): string {
  return value === undefined || value === null ? "not available" : String(value);
}

export function meterHtml(value: unknown): string {
  const snapshot = asRecord(value);
  const summary = asRecord(snapshot.summary);
  const activity = asRecord(snapshot.activity);
  const latest = asRecord(activity.latest_stage);
  const rows: Array<[string, string]> = [
    ["Stages measured", scalar(summary.stages_measured)],
    ["Measured build time", summary.build_wall_ms === undefined ? "not available" : `${summary.build_wall_ms} ms`],
    ["Model calls", scalar(summary.build_model_calls)],
    ["Build tokens", summary.tokens_reported_by_modules === true ? scalar(summary.build_tokens) : "not reported by modules"],
    ["Runs observed", scalar(activity.runs_observed)],
    ["Stage success rate", activity.stage_success_rate === undefined || activity.stage_success_rate === null ? "not available" : `${Number(activity.stage_success_rate) * 100}%`],
    ["Last measurement", scalar(snapshot.last_measurement_at)],
    ["Latest stage", Object.keys(latest).length ? `${scalar(latest.module)}:${scalar(latest.stage)} (${latest.ok === true ? "ok" : "failed"})` : "none yet"],
  ];
  const body = rows.map(([label, entry]) => `<tr><th>${escapeHtml(label)}</th><td>${escapeHtml(entry)}</td></tr>`).join("");
  const note = escapeHtml(scalar(summary.note));
  return `<!doctype html><html><body><h2>FactoryLine Meter</h2><table>${body}</table><p>${note}</p><p><small>Local receipt data only. Token totals require module-reported usage.</small></p></body></html>`;
}
