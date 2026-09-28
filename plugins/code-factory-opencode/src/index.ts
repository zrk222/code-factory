import { type Plugin, tool } from "@opencode-ai/plugin";
import { createHash } from "node:crypto";
import { realpath } from "node:fs/promises";
import {
  LANES,
  type Lane,
  type Result,
  audit,
  findings,
  summary,
} from "@factoryline/proof-client";

type Observation = { results: Result[]; revision: number };
type State = {
  root: string;
  observations: Map<string, Observation>;
  running: Set<string>;
  pending: Set<string>;
  fingerprints: Map<string, string>;
  notifications: Map<string, string>;
  revision: number;
  busy: boolean;
};
type Options = Record<string, unknown>;
type AuditContext = {
  sessionID: string;
  directory: string;
  worktree?: string;
  abort: AbortSignal;
  ask: (request: any) => Promise<void>;
  metadata: (value: { title: string }) => void;
};

function makeState(root: string): State {
  return {
    root,
    observations: new Map(),
    running: new Set(),
    pending: new Set(),
    fingerprints: new Map(),
    notifications: new Map(),
    revision: 0,
    busy: false,
  };
}

function makeText(state: State) {
  return (sessionID: string): string => {
    const observation = state.observations.get(sessionID);
    return summary(
      observation?.results || [],
      observation ? observation.revision !== state.revision : false,
    );
  };
}

function commandFor(options: Options, name: string, fallback: string): string {
  const value = options[name];
  return typeof value === "string" ? value : fallback;
}

function invalidate(state: State): void {
  state.revision += 1;
}

function isSourceFile(file: string): boolean {
  const normalized = file.replace(/\\/g, "/");
  return !/(?:^|\/)(?:\.factory|\.forge|\.git|node_modules|dist|build|\.opencode)(?:\/|$)/.test(
    normalized,
  );
}

function trimObservations(state: State): void {
  if (state.observations.size < 100) return;

  const oldestIdle = [...state.observations.keys()].find(
    (sessionID) => !state.running.has(sessionID),
  );
  if (!oldestIdle) return;

  state.observations.delete(oldestIdle);
  state.notifications.delete(oldestIdle);
}

async function runLane(
  state: State,
  lane: Lane,
  options: Options,
  signal?: AbortSignal,
  timeoutMs?: number,
): Promise<Result> {
  return audit(state.root, lane, {
    factory: commandFor(options, "factoryCommand", "factory"),
    forge: commandFor(options, "forgeCommand", "forge"),
    ...(signal ? { signal } : {}),
    ...(timeoutMs ? { timeoutMs } : {}),
  });
}

async function runAutomaticAudit(
  state: State,
  sessionID: string,
  options: Options,
): Promise<void> {
  if (state.busy) return;

  state.busy = true;
  state.running.add(sessionID);
  const observation: Observation = {
    results: [],
    revision: state.revision,
  };
  state.observations.set(sessionID, observation);

  try {
    for (const lane of Object.keys(LANES) as Lane[]) {
      observation.results.push(
        await runLane(state, lane, options, undefined, 60_000),
      );
    }
  } catch {
    // Missing lanes stay visible as missing evidence in the summary.
  } finally {
    state.busy = false;
    state.running.delete(sessionID);
  }
}

function evidenceTool(textFor: ReturnType<typeof makeText>) {
  return tool({
    description:
      "Read this session's CF and ForgeLine observations without running commands. Reports missing or stale evidence. Call before the final build summary.",
    args: {},
    async execute(_args, context) {
      return textFor(context.sessionID);
    },
  });
}

function findingTool(state: State) {
  return tool({
    description:
      "Read up to 20 existing audit findings for an actionable repair handoff; no source editing or execution.",
    args: {
      lane: tool.schema.enum([
        "review",
        "architecture",
        "security",
        "runtime",
        "forgeline",
      ]),
    },
    async execute({ lane }, context) {
      return findingForSession(state, lane, context.sessionID);
    },
  });
}

function findingForSession(
  state: State,
  lane: Lane,
  sessionID: string,
): string {
  const observation = state.observations.get(sessionID);
  const result = observation?.results.find((item) => item.lane === lane);
  if (!result || !observation) {
    return `${LANES[lane].label}: NOT_RUN. Run cf_audit for this lane.`;
  }

  return JSON.stringify({
    state: observation.revision !== state.revision ? "STALE" : result.state,
    candidateBinding: result.candidateBinding,
    limit: result.limit,
    findings: findings(result).slice(0, 20),
    nextAction:
      "Inspect the reported finding, repair within the agreed scope, then rerun verification. An empty list is not approval.",
  });
}

function setupConfig(config: any): void {
  config.command ??= {};
  config.command["cf-audit"] ??= {
    description:
      "Run CF and ForgeLine, inspect gaps, and include both results in your summary",
    template:
      "Use cf_audit with scope all, then cf_evidence. Report CF and ForgeLine results, missing checks, and concrete next actions. Do not equate runtime readiness, static inventory, or UNBOUND observations with passed runtime verification. $ARGUMENTS",
  };
}

function auditTool(
  state: State,
  options: Options,
  textFor: ReturnType<typeof makeText>,
) {
  return tool({
    description:
      "Run fixed local CF audit lanes and/or ForgeLine inventory. Results include failures and portability limits. Requires native audit permission. Include CF and ForgeLine results in the final build summary.",
    args: {
      scope: tool.schema
        .enum(["all", "review", "architecture", "security", "runtime", "forgeline"])
        .default("all"),
    },
    async execute({ scope }, context) {
      return executeAudit(state, options, textFor, scope, context);
    },
  });
}

async function executeAudit(
  state: State,
  options: Options,
  textFor: ReturnType<typeof makeText>,
  scope: Lane | "all",
  context: AuditContext,
): Promise<string> {
  const contextRoot = await realpath(context.worktree || context.directory);
  if (contextRoot !== state.root) {
    throw new Error("Session workspace differs from this plugin's workspace.");
  }
  if (state.busy) {
    return "An audit is already running in this workspace. Wait for it or cancel the active tool.";
  }

  state.busy = true;
  state.running.add(context.sessionID);
  try {
    await context.ask({
      permission: "cf_audit",
      patterns: [scope],
      always: ["*"],
      metadata: { workspace: state.root, scope },
    });
    trimObservations(state);

    const observation: Observation = {
      results: [],
      revision: state.revision,
    };
    state.observations.set(context.sessionID, observation);
    const lanes = scope === "all" ? (Object.keys(LANES) as Lane[]) : [scope];
    for (const lane of lanes) {
      if (context.abort.aborted) break;
      context.metadata({ title: LANES[lane].label });
      observation.results.push(
        await runLane(state, lane, options, context.abort),
      );
    }
    return textFor(context.sessionID);
  } finally {
    state.busy = false;
    state.running.delete(context.sessionID);
  }
}

function showToast(client: any, message: string) {
  return client.tui.showToast({
    body: {
      title: "FactoryLine audit evidence",
      message,
      variant: "info",
    },
  });
}

function deleteSession(state: State, sessionID: string): void {
  state.observations.delete(sessionID);
  state.notifications.delete(sessionID);
  state.pending.delete(sessionID);
  state.fingerprints.delete(sessionID);
}

async function onIdle(
  state: State,
  sessionID: string,
  autoAudit: boolean,
  options: Options,
  client: any,
  textFor: ReturnType<typeof makeText>,
): Promise<void> {
  if (startAutomaticAudit(state, sessionID, autoAudit, options, client)) return;
  await notifyEvidence(state, sessionID, options, client, textFor);
}

function startAutomaticAudit(
  state: State,
  sessionID: string,
  autoAudit: boolean,
  options: Options,
  client: any,
): boolean {
  if (!autoAudit || !state.pending.has(sessionID) || state.busy) return false;

  state.pending.delete(sessionID);
  void runAutomaticAudit(state, sessionID, options).then(() => {
    if (options.notifications === false) return;
    return showToast(
      client,
      "CF and ForgeLine audit observations are ready. Use cf_evidence to inspect results and limits.",
    ).catch(() => undefined);
  });
  return true;
}

async function notifyEvidence(
  state: State,
  sessionID: string,
  options: Options,
  client: any,
  textFor: ReturnType<typeof makeText>,
): Promise<void> {
  if (options.notifications === false) return;
  const observation = state.observations.get(sessionID);
  if (!observation) return;

  const body = textFor(sessionID);
  if (state.notifications.get(sessionID) === body) return;
  state.notifications.set(sessionID, body);
  const message =
    observation.revision !== state.revision
      ? "Evidence is stale. Rerun CF + ForgeLine for the updated work."
      : "Audit observations available. Use cf_evidence for results and limits.";
  await showToast(client, message).catch(() => undefined);
}

function diffEvent(state: State, properties: any): void {
  const sessionID = properties.sessionID;
  const digest = createHash("sha256")
    .update(JSON.stringify(properties.diff))
    .digest("hex");
  if (state.fingerprints.get(sessionID) === digest) return;

  state.fingerprints.set(sessionID, digest);
  invalidate(state);
  state.pending.add(sessionID);
}

async function onEvent(
  state: State,
  autoAudit: boolean,
  options: Options,
  client: any,
  textFor: ReturnType<typeof makeText>,
  { event }: any,
): Promise<void> {
  invalidateForFileEvent(state, event);
  recordDiffEvent(state, event);
  await handleSessionEvent(state, autoAudit, options, client, textFor, event);
}

function invalidateForFileEvent(state: State, event: any): void {
  if (!isSourceEditEvent(event)) return;
  invalidate(state);
}

function isSourceEditEvent(event: any): boolean {
  const sourceEvent = event.type === "file.edited" || event.type === "file.watcher.updated";
  return sourceEvent && typeof event.properties?.file === "string" && isSourceFile(event.properties.file);
}

function recordDiffEvent(state: State, event: any): void {
  if (!hasChangedDiff(event)) return;
  diffEvent(state, event.properties);
}

function hasChangedDiff(event: any): boolean {
  return event.type === "session.diff" && Array.isArray(event.properties?.diff) && event.properties.diff.length > 0;
}

async function handleSessionEvent(
  state: State,
  autoAudit: boolean,
  options: Options,
  client: any,
  textFor: ReturnType<typeof makeText>,
  event: any,
): Promise<void> {
  if (event.type === "session.deleted") deleteSession(state, event.properties?.info?.id);
  if (event.type !== "session.idle") return;
  await onIdle(state, event.properties?.sessionID, autoAudit, options, client, textFor);
}

function markPendingEdit(state: State, input: any): void {
  if (!["edit", "write", "apply_patch", "multiedit"].includes(input.tool)) {
    return;
  }
  invalidate(state);
  state.pending.add(input.sessionID);
}

function makeHooks(
  state: State,
  options: Options,
  client: any,
  textFor: ReturnType<typeof makeText>,
) {
  return {
    config: async (config: any) => setupConfig(config),
    tool: {
      cf_audit: auditTool(state, options, textFor),
      cf_evidence: evidenceTool(textFor),
      cf_findings: findingTool(state),
    },
    "tool.execute.before": async (input: any) => markPendingEdit(state, input),
    event: (arg: any) =>
      onEvent(
        state,
        options.autoAudit !== false,
        options,
        client,
        textFor,
        arg,
      ),
    "experimental.chat.system.transform": async (_input: any, output: any) => {
      output.system.push(
        "FactoryLine tools are available. After implementation, use cf_audit then cf_evidence and include both CF and ForgeLine states and scope limits in the final build summary. Ask through native permissions before execution. If an audit was not run, report NOT_RUN. Static inventory, runtime readiness and UNBOUND observations do not establish runtime correctness or release approval.",
      );
    },
    "experimental.session.compacting": async (input: any, output: any) => {
      output.context.push(
        `FactoryLine evidence handoff (observations only):\n${textFor(input.sessionID)}`,
      );
    },
  };
}

const FactoryLinePlugin: Plugin = async (
  { client, directory, worktree },
  options = {},
) => {
  const root = await realpath(worktree || directory);
  const state = makeState(root);
  return makeHooks(state, options, client, makeText(state));
};

export default FactoryLinePlugin;
