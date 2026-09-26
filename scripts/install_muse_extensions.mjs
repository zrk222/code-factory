// Install the supported standalone Muse Code surfaces for this package.
// Use this when the host build does not expose the preview plugin commands.
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
let dryRun = false;
let configHome = path.resolve(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'));
for (let index = 0; index < args.length; index += 1) {
  if (args[index] === '--dry-run') {
    dryRun = true;
  } else if (args[index] === '--config-home' && args[index + 1]) {
    configHome = path.resolve(args[index + 1]);
    index += 1;
  } else {
    throw new Error('usage: node scripts/install_muse_extensions.mjs [--dry-run] [--config-home PATH]');
  }
}

const museHome = path.join(configHome, 'muse');
const installRoot = path.join(museHome, 'extensions', 'code-factory');
const hookSource = path.join(repoRoot, 'plugins', 'muse-code-factory-audit', 'hooks', 'audit.mjs');
const hookLauncherSource = path.join(repoRoot, 'plugins', 'muse-code-factory-audit', 'hooks', 'standalone.mjs');
const mcpSource = path.join(repoRoot, 'plugins', 'muse-expertise-agent-workflows', 'mcp', 'server.mjs');
const auditMcpSource = path.join(repoRoot, 'plugins', 'muse-code-factory-audit', 'mcp', 'server.mjs');
const hookDirectory = path.join(installRoot, 'hooks');
const hookTarget = path.join(hookDirectory, 'standalone.mjs');
const mcpTarget = path.join(installRoot, 'expertise', 'server.mjs');
const auditMcpTarget = path.join(installRoot, 'audit', 'server.mjs');
const skills = [
  {
    id: 'cf-fl-build-audit',
    source: path.join(repoRoot, 'plugins', 'muse-code-factory-audit', 'skills', 'cf-fl-build-audit', 'SKILL.md'),
  },
  {
    id: 'expertise-agent-workflows',
    source: path.join(repoRoot, 'plugins', 'muse-expertise-agent-workflows', 'skills', 'expertise-agent-workflows', 'SKILL.md'),
  },
];
for (const source of [hookSource, hookLauncherSource, mcpSource, auditMcpSource, ...skills.map((item) => item.source)]) {
  if (!existsSync(source)) throw new Error(`Required Muse extension file is missing: ${source}`);
}

function loadSettings() {
  const settingsPath = path.join(museHome, 'settings.json');
  let settings = { schema_version: 1 };
  if (existsSync(settingsPath)) {
    try {
      settings = JSON.parse(readFileSync(settingsPath, 'utf8'));
    } catch (error) {
      throw new Error(`Refusing to replace invalid Muse settings: ${error.message}`);
    }
  }
  if (!settings || typeof settings !== 'object' || Array.isArray(settings) || settings.schema_version !== 1) {
    throw new Error('Muse settings must be a JSON object with schema_version 1.');
  }
  for (const key of ['hooks', 'mcpServers']) {
    if (settings[key] != null && (typeof settings[key] !== 'object' || Array.isArray(settings[key]))) {
      throw new Error(`Refusing to replace malformed Muse settings member: ${key}`);
    }
  }
  return settings;
}

function addHook(settings, event, matcher, statusMessage) {
  settings.hooks ||= {};
  const groups = settings.hooks[event] ?? [];
  if (!Array.isArray(groups)) throw new Error(`Refusing to replace malformed hooks.${event}.`);
  let group = groups.find((item) => (item.matcher ?? '') === (matcher ?? ''));
  if (!group) {
    group = matcher ? { matcher, hooks: [] } : { hooks: [] };
    groups.push(group);
  }
  if (!Array.isArray(group.hooks)) throw new Error(`Refusing to replace malformed hooks.${event} matcher group.`);
  const command = `node "${hookTarget.replaceAll('"', '\\"')}"`;
  const timeout = event === 'Stop' ? 10 : 240;
  const managedHook = group.hooks.find((handler) => handler.type === 'command' && handler.command === command);
  if (managedHook) {
    managedHook.timeout = timeout;
    managedHook.statusMessage = statusMessage;
  } else group.hooks.push({ type: 'command', command, timeout, statusMessage });
  settings.hooks[event] = groups;
}

function configuredSettings() {
  const settings = loadSettings();
  const obsoleteHookCommand = `node "${path.join(installRoot, 'hooks', 'build-audit.mjs').replaceAll('"', '\\"')}"`;
  for (const groups of Object.values(settings.hooks || {})) {
    if (!Array.isArray(groups)) continue;
    for (const group of groups) {
      if (!Array.isArray(group?.hooks)) continue;
      group.hooks = group.hooks.filter((handler) => !(
        handler.type === 'command' && handler.command === obsoleteHookCommand
      ));
    }
  }
  addHook(settings, 'PostToolUse', 'Bash|shell|Edit|Write|MultiEdit|NotebookEdit|ApplyPatch', 'Running bounded Code Factory and ForgeLine checks; full-depth penetration remains incomplete');
  addHook(settings, 'PostToolUseFailure', 'Bash|shell|Edit|Write|MultiEdit|NotebookEdit|ApplyPatch', 'Checking bounded audit results and actionable resolutions after a failed build');
  addHook(settings, 'Stop', undefined, 'Checking final audit outcomes and required next actions');
  settings.mcpServers ||= {};
  const desired = {
    type: 'stdio',
    command: process.execPath,
    args: [mcpTarget],
    cwd: installRoot,
  };
  for (const [id, config] of Object.entries({
    'expertise-agent-workflows': desired,
    'muse-code-factory-audit': { ...desired, args: [auditMcpTarget] },
  })) {
    const existing = settings.mcpServers[id];
    if (existing && JSON.stringify(existing) !== JSON.stringify(config)) {
      const pointsToManagedInstall = Array.isArray(existing.args) &&
        existing.args.some((value) => typeof value === 'string' && value.includes(`${path.sep}extensions${path.sep}code-factory${path.sep}`));
      if (!pointsToManagedInstall) {
        throw new Error(`Muse MCP server id \`${id}\` is already configured differently; refusing to replace it.`);
      }
    }
    settings.mcpServers[id] = config;
  }
  return settings;
}

const settingsPath = path.join(museHome, 'settings.json');
const settings = configuredSettings();
const plan = {
  mode: 'standalone-muse-code',
  reason: 'This Muse build does not provide the plugin-management command; skills, user hooks, and a stdio MCP server are native supported extension points.',
  settingsPath,
  hookPath: hookTarget,
  mcpServerPath: mcpTarget,
  auditMcpServerPath: auditMcpTarget,
  skills: skills.map(({ id }) => id),
  hookEvents: ['PostToolUse:Bash|shell|Edit|Write|MultiEdit|NotebookEdit|ApplyPatch', 'PostToolUseFailure:Bash|shell|Edit|Write|MultiEdit|NotebookEdit|ApplyPatch', 'Stop'],
  mcpServer: 'expertise-agent-workflows',
  auditMcpServer: 'muse-code-factory-audit',
  toolNames: [
    'expertise_earnie_vendor_value_review',
    'expertise_cluso_account_impact_review',
    'expertise_surely_portfolio_watch',
    'cf_audit_run', 'cf_audit_status', 'cf_audit_findings', 'cf_audit_coverage', 'cf_pr_review_brief',
  ],
};

if (!dryRun) {
  mkdirSync(path.dirname(hookTarget), { recursive: true });
  mkdirSync(path.dirname(mcpTarget), { recursive: true });
  mkdirSync(path.dirname(auditMcpTarget), { recursive: true });
  copyFileSync(hookSource, path.join(hookDirectory, 'audit.mjs'));
  copyFileSync(hookLauncherSource, hookTarget);
  copyFileSync(mcpSource, mcpTarget);
  copyFileSync(auditMcpSource, auditMcpTarget);
  for (const skill of skills) {
    const directory = path.join(museHome, 'skills', skill.id);
    mkdirSync(directory, { recursive: true });
    copyFileSync(skill.source, path.join(directory, 'SKILL.md'));
  }
  mkdirSync(museHome, { recursive: true });
  const temporaryPath = `${settingsPath}.code-factory-tmp`;
  writeFileSync(temporaryPath, `${JSON.stringify(settings, null, 2)}\n`, 'utf8');
  renameSync(temporaryPath, settingsPath);
  plan.installed = true;
} else {
  plan.installed = false;
}
process.stdout.write(`${JSON.stringify(plan)}\n`);
