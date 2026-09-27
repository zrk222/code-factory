# Code Factory Build Audit for Muse Code

This package brings Code Factory's bounded local code review into Muse Code
through supported user hooks, a skill, and a stdio MCP server that does not
modify project source. It is for reviewing work in a local Git workspace; it is
not a Meta AI Connector or a hosted service.

## Install

From the Code Factory repository root, run:

```powershell
node scripts/install_muse_extensions.mjs
```

Restart Muse Code so it reloads its user settings, then confirm the skill is
available:

```powershell
muse skills list --source user
```

The installer writes managed runtime files under the Muse user configuration
directory and merges the managed hooks and MCP servers into `settings.json`.
It preserves unrelated settings and fails rather than replacing a conflicting
MCP server entry. This is the supported installation path for Muse Code
1.3.0, whose installed build does not expose the plugin-management command.
The `.muse-plugin/plugin.json` manifest remains the native package definition
for plugin-capable Muse builds.

## What it does

Automatic hooks run bounded Code Factory and ForgeLine checks after relevant
build, test, lint, edit, and patch events. The `cf-fl-build-audit` skill tells
Muse how to interpret the result and keep incomplete coverage explicit. The
stdio MCP server exposes five tools:

- `cf_audit_run` runs the bounded checks for a local Git workspace.
- `cf_audit_status` returns the current receipt status and finding counts.
- `cf_audit_findings` pages through the findings retained in that receipt.
- `cf_audit_coverage` summarizes recorded scope and coverage limits.
- `cf_pr_review_brief` produces a concise review handoff from the receipt.

The MCP tools accept an absolute local workspace path. Receipts are bound to
the Git head, worktree digest, and audit-policy digest; stale, expired, or
tampered receipts are rejected. A fresh `cf_audit_run` is required after
workspace or policy changes.

## Data and authority

The extension runs locally. It does not implement a hosted API or upload source
code. The hook invokes the locally installed `rtk` and `forge` command-line
tools; their own network use and configuration are outside this package. Local
audit state and receipts are written under `MUSE_PLUGIN_DATA_DIR` when set, or
under the operating system's temporary directory otherwise. Receipts expire
after 24 hours; older state is eligible for cleanup after seven days.

Results are advisory evidence. The Python security scan covers Python ASTs;
Code Factory pattern and guard-path checks require the repository's
`.factory/review-audits.json`; ForgeLine `qa --repo-wide` is an inventory check.
These hooks do not execute arbitrary project test commands, provide complete
cross-language or runtime penetration coverage, certify software, or approve a
PR, release, publication, or deployment. The recorded full-depth penetration
outcome remains `incomplete` until that separate pipeline is implemented and
executed.

## Meta connector submission boundary

This local Muse Code package is not the hosted Meta AI Connector requested for
the Meta AI app or web. The current package does not provide a public HTTPS
REST/MCP endpoint, OAuth account linking, hosted operations, or production
privacy/terms pages. The Meta AI Connectors developer preview currently asks
for a live REST API or one in active development, a clear use case, and OAuth
account linking. Muse's connector platform separately reviews functionality,
security, legal requirements, and end-to-end behavior. Do not submit this local
package as evidence that those hosted requirements are satisfied.

## Validate locally

Run the focused package and runtime coverage from the repository root:

```powershell
python -m pytest tests/test_langchain_plugin.py -q
node --check plugins/muse-code-factory-audit/mcp/server.mjs
node --check plugins/muse-code-factory-audit/hooks/audit.mjs
```

The installed Muse build may not provide a native plugin validator. A passing
local test is not Meta's end-to-end review or store approval.
