import type { SourceWorkerDependencies, WorkerObservation, WorkerSourceDefinition } from "./sourceWorker.js";
import { runSourceMonitoringCycle } from "./sourceWorker.js";
import { parseWorkerIdentityConfig, parseWorkerVaultMount, type WorkerIdentityConfig } from "./sourceWorkerCredentials.js";

export type WorkerServiceConfig = {
  convexUrl: string;
  agentSpecId: string;
  identity: WorkerIdentityConfig;
  vaultMount?: string;
  pollIntervalMs: number;
  healthPort: number;
  alertWebhookUrl?: string;
};

export type WorkerServiceState = {
  startedAt: number;
  cycleRunning: boolean;
  lastCycleStartedAt?: number;
  lastCycleCompletedAt?: number;
  lastCycleSucceededAt?: number;
  lastErrorCode?: string;
  lastAlertErrorCode?: string;
  sourcesObserved: number;
  failedSources: number;
};

export type WorkerControlPlane = {
  authenticate?: () => Promise<void>;
  listSources: () => Promise<WorkerSourceDefinition[]>;
  recordObservation: (observation: WorkerObservation) => Promise<void>;
};

export type WorkerAlertSink = (event: { code: string; failedSources: number; observedSources: number; occurredAt: number }) => Promise<void>;

const ALERT_RETRY_BACKOFF_MS = [250, 1000] as const;

function required(config: Record<string, string | undefined>, key: string) {
  const value = config[key]?.trim();
  if (!value) throw new Error(`E_SOURCE_WORKER_CONFIG_${key}`);
  return value;
}

function httpsUrl(value: string, code: string) {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(code); }
  if (url.protocol !== "https:" || url.username || url.password) throw new Error(code);
  return url.toString();
}

/** Parses fail-closed worker configuration without logging or returning environment contents. */
export function parseWorkerServiceConfig(environment: Record<string, string | undefined>): WorkerServiceConfig {
  const pollSeconds = Number(environment.SOURCE_WORKER_POLL_SECONDS ?? "60");
  const healthPort = Number(environment.SOURCE_WORKER_HEALTH_PORT ?? "8080");
  if (!Number.isInteger(pollSeconds) || pollSeconds < 15 || pollSeconds > 86_400) throw new Error("E_SOURCE_WORKER_CONFIG_POLL_SECONDS");
  if (!Number.isInteger(healthPort) || healthPort < 1024 || healthPort > 65_535) throw new Error("E_SOURCE_WORKER_CONFIG_HEALTH_PORT");
  return {
    convexUrl: httpsUrl(required(environment, "CONVEX_URL"), "E_SOURCE_WORKER_CONFIG_CONVEX_URL"),
    agentSpecId: required(environment, "SOURCE_WORKER_AGENT_SPEC_ID"),
    identity: parseWorkerIdentityConfig(environment),
    vaultMount: parseWorkerVaultMount(environment),
    pollIntervalMs: pollSeconds * 1000,
    healthPort,
    alertWebhookUrl: environment.SOURCE_WORKER_ALERT_WEBHOOK_URL ? httpsUrl(environment.SOURCE_WORKER_ALERT_WEBHOOK_URL, "E_SOURCE_WORKER_CONFIG_ALERT_WEBHOOK") : undefined,
  };
}

/** Delivers a content-free alert with bounded retries for transient delivery failures. */
export async function deliverWorkerAlert(alert: WorkerAlertSink, event: Parameters<WorkerAlertSink>[0], sleep: (milliseconds: number) => Promise<void>) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      await alert(event);
      return;
    } catch {
      if (attempt === 2) throw new Error("E_SOURCE_WORKER_ALERT_FAILED");
      await sleep(ALERT_RETRY_BACKOFF_MS[attempt]);
    }
  }
}

/** Runs one content-free monitoring cycle and updates inspectable worker health. */
export async function executeWorkerCycle(control: WorkerControlPlane, dependencies: SourceWorkerDependencies, state: WorkerServiceState, alert: WorkerAlertSink): Promise<WorkerObservation[]> {
  if (state.cycleRunning) throw new Error("E_SOURCE_WORKER_CYCLE_OVERLAP");
  state.cycleRunning = true;
  state.lastCycleStartedAt = dependencies.now();
  state.sourcesObserved = 0;
  state.failedSources = 0;
  state.lastAlertErrorCode = undefined;
  const notify = async (event: Parameters<WorkerAlertSink>[0]) => {
    try { await deliverWorkerAlert(alert, event, dependencies.sleep); }
    catch { state.lastAlertErrorCode = "E_SOURCE_WORKER_ALERT_FAILED"; }
  };
  try {
    await control.authenticate?.();
    const sources = await control.listSources();
    const observations = await runSourceMonitoringCycle(sources, dependencies);
    for (const observation of observations) await control.recordObservation(observation);
    state.sourcesObserved = observations.length;
    state.failedSources = observations.filter((observation) => observation.outcome === "failure").length;
    state.lastCycleCompletedAt = dependencies.now();
    if (state.failedSources === 0) {
      state.lastCycleSucceededAt = state.lastCycleCompletedAt;
      state.lastErrorCode = undefined;
    } else {
      state.lastErrorCode = "SOURCE_WORKER_SOURCE_FAILURES";
      await notify({ code: state.lastErrorCode, failedSources: state.failedSources, observedSources: state.sourcesObserved, occurredAt: state.lastCycleCompletedAt });
    }
    return observations;
  } catch (error) {
    state.lastCycleCompletedAt = dependencies.now();
    state.lastErrorCode = error instanceof Error && /^E_[A-Z0-9_]+$/.test(error.message) ? error.message : "E_SOURCE_WORKER_CYCLE_FAILED";
    await notify({ code: state.lastErrorCode, failedSources: state.failedSources, observedSources: state.sourcesObserved, occurredAt: state.lastCycleCompletedAt });
    throw error;
  } finally {
    state.cycleRunning = false;
  }
}

/** Computes process health without treating external publisher availability as process failure. */
export function workerHealth(state: WorkerServiceState, now: number, pollIntervalMs: number) {
  const alive = now - state.startedAt >= 0;
  const ready = state.lastCycleSucceededAt !== undefined && now - state.lastCycleSucceededAt <= pollIntervalMs * 3 && state.failedSources === 0 && state.lastErrorCode === undefined;
  return { alive, ready, cycleRunning: state.cycleRunning, lastCycleCompletedAt: state.lastCycleCompletedAt ?? null, sourcesObserved: state.sourcesObserved, failedSources: state.failedSources, lastErrorCode: state.lastErrorCode ?? null, lastAlertErrorCode: state.lastAlertErrorCode ?? null };
}

/** Waits a bounded period for an in-flight cycle before a process exits. */
export async function waitForWorkerIdle(state: WorkerServiceState, timeoutMs: number, now: () => number, sleep: (milliseconds: number) => Promise<void>) {
  const deadline = now() + timeoutMs;
  while (state.cycleRunning && now() < deadline) await sleep(Math.min(50, Math.max(1, deadline - now())));
  return !state.cycleRunning;
}
