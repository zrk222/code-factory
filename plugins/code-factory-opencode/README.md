# Code Factory for OpenCode

Native OpenCode plugin for local Code Factory and ForgeLine checks. It adds
`cf_audit`, `cf_evidence`, `cf_findings`, and `/cf-audit` to OpenCode. A change
to the active session triggers a bounded CF + ForgeLine scan when the session
becomes idle. The summary names every lane, including missing, failed, stale,
and unavailable checks.

## Install for a project

Build this repository's plugin:

```sh
cd plugins/code-factory-opencode
npm ci
npm run build
```

Copy `dist/index.js` to `<your-project>/.opencode/plugins/factoryline.js`.
The GitHub **OpenCode native plugin** workflow also packages a versioned
`code-factory-opencode-0.1.0.tgz` artifact. Unpack that artifact and copy its
`package/dist/index.js` into the project plugin path. This is a native
OpenCode project plugin; no OpenCode Marketplace listing is implied.
OpenCode automatically loads project plugins from that folder. The built file
includes the OpenCode plugin SDK and the shared audit client, so the target
project needs no npm install. Install the `factory` and `forge` CLIs in the
environment running OpenCode. OpenCode asks for its native `cf_audit`
permission on an explicit tool call. Automatic post-edit scans are part of
enabling this project plugin; remove the file or configure the plugin with
`autoAudit: false` when automatic local scanning is not wanted.

For all current observations, run `/cf-audit`, or ask the agent to call
`cf_audit` with `scope: "all"` and then `cf_evidence`.

The plugin invokes fixed CLI argument lists with no shell and caps each lane
at 60 seconds for automatic scans. It does not start a worker, modify source,
or authorize a release. CF pattern and guard-path audits need a project's
`.factory/review-audits.json`; the security lane is a bounded Python static
scan; the ForgeLine lane is a repository inventory. Results are local,
`UNBOUND` observations until a separate candidate verification runs.

The existing `factory mcp config --client opencode` remains available when an
agent only needs the read-only Code Factory MCP tools.
