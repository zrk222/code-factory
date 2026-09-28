import { type Plugin, tool } from "@opencode-ai/plugin";
import { realpath } from "node:fs/promises";
import { createHash } from "node:crypto";
import { LANES, type Lane, type Result, audit, summary, findings } from "@factoryline/proof-client";

type Observation = { results: Result[]; revision: number };

const FactoryLinePlugin: Plugin = async ({ client, directory, worktree }, options = {}) => {
  const root = await realpath(worktree || directory);
  const observations = new Map<string, Observation>();
  const running = new Set<string>();
  const pending = new Set<string>();
  const diffFingerprints = new Map<string, string>();
  const notifications = new Map<string, string>();
  let revision = 0;
  let workspaceBusy = false;
  const autoAudit = options.autoAudit !== false;
  const command = (name: string, fallback: string): string => typeof options[name] === "string" ? options[name] as string : fallback;
  const text = (sessionID: string): string => {
    const value = observations.get(sessionID);
    return summary(value?.results || [], value ? value.revision !== revision : false);
  };
  const invalidate = (): void => { revision += 1; };
  const isSource = (file: string): boolean => {
    const normalized = file.replace(/\\/g, "/");
    return !/(?:^|\/)(?:\.factory|\.forge|\.git|node_modules|dist|build|\.opencode)(?:\/|$)/.test(normalized);
  };
  const trim = (): void => {
      if (observations.size < 100) return;
    const key = [...observations.keys()].find(id => !running.has(id));
    if (key) { observations.delete(key); notifications.delete(key); }
  };
  const runAutomatic = async (sessionID: string): Promise<void> => {
    if (workspaceBusy) return;
    workspaceBusy = true; running.add(sessionID);
    const snapshot: Observation = { results: [], revision };
    observations.set(sessionID, snapshot);
    try {
      for (const lane of Object.keys(LANES) as Lane[]) {
        snapshot.results.push(await audit(root, lane, { factory: command("factoryCommand", "factory"), forge: command("forgeCommand", "forge"), timeoutMs: 60000 }));
      }
    } catch { /* Each audit lane reports its own closed state; unexpected failures remain visible as missing lanes. */ }
    finally { workspaceBusy = false; running.delete(sessionID); }
  };

  return {
    config: async config => {
      config.command ??= {};
      config.command["cf-audit"] ??= {
        description: "Run CF and ForgeLine, inspect gaps, and include both results in your summary",
        template: "Use cf_audit with scope all, then cf_evidence. Report CF and ForgeLine results, missing checks, and concrete next actions. Do not equate runtime readiness, static inventory, or UNBOUND observations with passed runtime verification. $ARGUMENTS",
      };
    },
    tool: {
      cf_audit: tool({
        description: "Run fixed local CF audit lanes and/or ForgeLine inventory. Results include failures and portability limits. Requires native audit permission. Include CF and ForgeLine results in the final build summary.",
        args: { scope: tool.schema.enum(["all", "review", "architecture", "security", "runtime", "forgeline"]).default("all") },
        async execute({ scope }, context) {
          if (await realpath(context.worktree || context.directory) !== root) throw new Error("Session workspace differs from this plugin's workspace.");
          if (workspaceBusy) return "An audit is already running in this workspace. Wait for it or cancel the active tool.";
          workspaceBusy = true;
          running.add(context.sessionID);
          try {
            await context.ask({ permission: "cf_audit", patterns: [scope], always: ["*"], metadata: { workspace: root, scope } });
            trim();
            const snapshot: Observation = { results: [], revision };
            observations.set(context.sessionID, snapshot);
            const lanes = scope === "all" ? Object.keys(LANES) as Lane[] : [scope];
            for (const lane of lanes) {
              if (context.abort.aborted) break;
              context.metadata({ title: LANES[lane].label });
              snapshot.results.push(await audit(root, lane, { factory: command("factoryCommand", "factory"), forge: command("forgeCommand", "forge"), signal: context.abort }));
            }
            return text(context.sessionID);
          } finally { workspaceBusy = false; running.delete(context.sessionID); }
        },
      }),
      cf_evidence: tool({
        description: "Read this session's CF and ForgeLine observations without running commands. Reports missing or stale evidence. Call before the final build summary.",
        args: {},
        async execute(_args, context) { return text(context.sessionID); },
      }),
      cf_findings: tool({
        description: "Read up to 20 existing audit findings for an actionable repair handoff; no source editing or execution.",
        args: { lane: tool.schema.enum(["review", "architecture", "security", "runtime", "forgeline"]) },
        async execute({ lane }, context) {
          const value = observations.get(context.sessionID);
          const result = value?.results.find(item => item.lane === lane);
          if (!result) return `${LANES[lane].label}: NOT_RUN. Run cf_audit for this lane.`;
          return JSON.stringify({ state: value!.revision !== revision ? "STALE" : result.state, candidateBinding: result.candidateBinding, limit: result.limit, findings: findings(result).slice(0, 20), nextAction: "Inspect the reported finding, repair within the agreed scope, then rerun verification. An empty list is not approval." });
        },
      }),
    },
    "tool.execute.before": async input => {
      // Conservatively invalidate before potentially mutating tools, even when they fail.
      if (["edit", "write", "apply_patch", "multiedit"].includes(input.tool)) {
        invalidate(); pending.add(input.sessionID);
      }
    },
    event: async ({ event }) => {
      if ((event.type === "file.edited" || event.type === "file.watcher.updated") && isSource(event.properties.file)) invalidate();
      if (event.type === "session.diff" && event.properties.diff.length) {
        const digest = createHash("sha256").update(JSON.stringify(event.properties.diff)).digest("hex");
        if (diffFingerprints.get(event.properties.sessionID) !== digest) {
          diffFingerprints.set(event.properties.sessionID, digest); invalidate(); pending.add(event.properties.sessionID);
        }
      }
      if (event.type === "session.deleted") {
        const id = event.properties.info.id;
        observations.delete(id); notifications.delete(id); pending.delete(id); diffFingerprints.delete(id);
      }
      if (event.type !== "session.idle") return;
      const sessionID = event.properties.sessionID;
      if (autoAudit && pending.has(sessionID) && !workspaceBusy) {
        pending.delete(sessionID);
        void runAutomatic(sessionID).then(() => {
          if (options.notifications !== false) void client.tui.showToast({ body: { title: "FactoryLine audit evidence", message: "CF and ForgeLine audit observations are ready. Use cf_evidence to inspect results and limits.", variant: "info" } }).catch(() => undefined);
        });
        return;
      }
      if (options.notifications === false) return;
      const value = observations.get(sessionID);
      if (!value) return;
      const body = text(sessionID);
      if (notifications.get(sessionID) === body) return;
      notifications.set(sessionID, body);
      await client.tui.showToast({ body: { title: "FactoryLine audit evidence", message: value.revision !== revision ? "Evidence is stale. Rerun CF + ForgeLine for the updated work." : "Audit observations available. Use cf_evidence for results and limits.", variant: "info" } }).catch(() => undefined);
    },
    "experimental.chat.system.transform": async (_input, output) => {
      output.system.push("FactoryLine tools are available. After implementation, use cf_audit then cf_evidence and include both CF and ForgeLine states and scope limits in the final build summary. Ask through native permissions before execution. If an audit was not run, report NOT_RUN. Static inventory, runtime readiness and UNBOUND observations do not establish runtime correctness or release approval.");
    },
    "experimental.session.compacting": async (input, output) => {
      output.context.push(`FactoryLine evidence handoff (observations only):\n${text(input.sessionID)}`);
    },
  };
};

export default FactoryLinePlugin;
