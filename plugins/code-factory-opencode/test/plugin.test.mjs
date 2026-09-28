import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import FactoryLinePlugin from "../dist/index.js";

const root = path.resolve("../..");
const client = { tui: { showToast: async () => ({}) } };

test("native OpenCode hooks expose an audit command and explicit evidence tools", async () => {
  const hooks = await FactoryLinePlugin({ client, directory: root, worktree: root }, { autoAudit: false, notifications: false, factoryCommand: path.join(root, "missing-factory"), forgeCommand: path.join(root, "missing-forge") });
  const config = {};
  await hooks.config(config);
  assert.match(config.command["cf-audit"].template, /CF and ForgeLine/);
  const system = { system: [] };
  await hooks["experimental.chat.system.transform"]({}, system);
  assert.match(system.system[0], /NOT_RUN/);
  const context = { sessionID: "session-1", directory: root, worktree: root, abort: new AbortController().signal, ask: async () => {}, metadata: () => {} };
  assert.match(await hooks.tool.cf_evidence.execute({}, context), /ForgeLine repository inventory: NOT_RUN/);
  const audit = await hooks.tool.cf_audit.execute({ scope: "all" }, context);
  assert.match(audit, /CF security patterns: UNAVAILABLE/);
  assert.match(audit, /ForgeLine repository inventory: UNAVAILABLE/);
  await hooks["tool.execute.before"]({ tool: "edit", sessionID: "session-1", callID: "change" }, { args: {} });
  assert.match(await hooks.tool.cf_evidence.execute({}, context), /CF security patterns: STALE/);
  const compact = { context: [] };
  await hooks["experimental.session.compacting"]({ sessionID: "session-1" }, compact);
  assert.match(compact.context[0], /STALE/);
});
