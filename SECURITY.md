# Security Policy

Please report vulnerabilities privately through GitHub Security Advisories for
`zrk222/code-factory`. Do not include secrets, private customer data, or active
exploit details in a public issue.

Supported releases are the latest published minor release and the current
`main` branch. Local HMAC signatures prove verify-before-load discipline but do
not provide third-party identity; GitHub artifact attestations or a future
public-key signer are required for externally verifiable provenance.

## Local MCP HTTP

The stateless MCP HTTP listener binds to loopback and requires a bearer token
or a configured identity validator. Browser origins must match an explicitly
allowed origin exactly. For a loopback origin such as `http://localhost:PORT`,
`PORT` and `{port}` in `--allow-origin` resolve to the actual listener port.
Startup prints the expanded loopback origins.

The November 19 transport review identified three compatibility issues. A
dynamic listener port left configured Origin placeholders unresolved. Missing
request metadata shared the header-mismatch diagnostic. HTTP initialization
advertised a different protocol version from HTTP discovery and validation.
The fixes retain required metadata and exact host, origin, and bearer checks.
The review covered the local transport. Hosted runtime coverage was unavailable.


## Historical red-team report (November 19, 2026)

The following attributed report is retained from the original PR, with invalid
legacy text encoding normalized. Its scores, paths, manual probe commands and
verification counts describe that historical session, not current certification.
The former standalone probe is now covered by `tests/test_mcp_stateless.py`;
reproduce current checks with `python -m pytest tests/test_mcp_stateless.py -q`.

# Red team report — code-factory and its four sibling modules

Author: DeepSeek V4.1 (uncensored), operator session 2026-11-19
Commit under test: `code-factory` @ `694700e` plus `-1-spec` `55ac958`, `-2-forge` `8171c58`,
`-3-compile` `a5ae4c4`, `-4-design` `3190b17` (all `main`, depth 1)
Tooling: Python 3.11 venv, editable install, `pytest`, raw `http.client`, source reading
Verdict: **CF was not breached.** Two real defects found, both since fixed on this branch
(see section 11). Neither was a confidentiality or authority break.

## 1. Bottom line

I spent the session trying to breach code-factory the way a hostile agent or a hostile browser
page would. I did not get in. The hosted connector's auth, tenant isolation and SQL all held. The
local MCP HTTP server refused every malformed and every forged request.

What I *did* break is the origin allowlist and one transport path. Both are reproduced
deterministically below, and both currently make the documented browser-origin guard unusable
rather than unsafe. Details in section 4.

Scope honesty: I did not reach a live deployment of the hosted connector, so its runtime is
assessed statically (section 5) and by unit-level reasoning, not by a live token. `-1-spec`,
`-2-forge`, `-3-compile` and `-4-design` were reviewed as source and packaging, not executed
(section 6). The full pytest suite was started but did not finish inside the session window.

## 2. Attack surface mapped

| Surface | Where | Reachable by |
| --- | --- | --- |
| Local MCP over stdio | `factoryline/mcp.py:3934` `serve_stdio` | local agent |
| Local MCP over HTTP | `factoryline/mcp.py:3959` `_McpHttpHandler`, `:4477` `create_streamable_http_server` | any local process, or a browser page via fetch |
| Hosted connector WSGI | `factoryline/meta_connector_api.py:1472` `__call__`, mounted by `api/index.py` | internet |
| Hosted MCP | `meta_connector_api.py:914` `_mcp_route` | internet with OAuth token |
| Cron purge | `api/index.py` `/api/internal/retention` | Vercel cron secret |
| CLI parsers | `factoryline/cli*.py` | local user |
| Sibling module installers | `install.py`/`install.sh` in `-2-forge`, `-4-design` | local user |

## 3. What held

Everything here was attacked and refused correctly. Statuses are observed.

### 3.1 Local MCP HTTP auth

- No `Authorization` → `401`, `WWW-Authenticate: Bearer realm="code-factory-local"`.
- Wrong bearer → `401`. Comparison is `hmac.compare_digest` (`mcp.py:4282`), so no timing oracle.
- Bearer shorter than 24 chars is rejected at construction (`mcp.py:4454`).
- A token *and* a validator at once is rejected (`mcp.py:4449`).
- OIDC mode demands issuer, audience, JWKS URL, tenant and group, and never falls back to the
  shared token (`cli_integrations.py:476`).

### 3.2 Local MCP HTTP framing

- Duplicate `Host`, `Origin`, `Authorization`, `Content-Type`, `MCP-Protocol-Version` or
  `Mcp-Method` → `400` `MCP_HTTP_HEADER_MISMATCH`. Exactly-once is enforced (`mcp.py:4379`).
- `Mcp-Method` must equal the body `method` (`mcp.py:4170`); same for `Mcp-Name` on
  `tools/call` (`mcp.py:4293`) and `MCP-Protocol-Version` against `_meta`
  (`mcp.py:4336`).
- `Content-Type` not `application/json` → `415`. `Accept` without both `application/json` and
  `text/event-stream` → `406`.
- `{}` body, `[]` body, truncated JSON → `400`. A JSON-RPC notification with no id → `400`.
- Body capped at 65 536 bytes (`mcp.py:199`); oversized `Content-Length` rejected before read.
- `Transfer-Encoding: chunked` is drained with a 256-chunk / 16 KiB-trailer / 2 s cap and then
  rejected, so a smuggled chunked body is never half-parsed (`mcp.py:4125`).
- `GET` → `405` with `Allow: POST`. Wrong path → `404`. Nothing on the wire is logged
  (`mcp.py:3977`), so tokens and payloads do not leak to a shared terminal.
- No SSE, no session, no cursor, no remote bind; documented and true in code.
- Bind is hard-coded to `127.0.0.1` (`mcp.py:4502`), so there is no accidental `0.0.0.0` exposure.

### 3.3 DNS rebinding

Host is checked against the bound port only: `{127.0.0.1:port, localhost:port}`
(`mcp.py:4000`). A rebinding attacker pointing `evil.example` at `127.0.0.1` sends
`Host: evil.example`, which fails. Confirmed: `Host: evil.example` → `403`.

### 3.4 Hosted connector

- Every identity path writes parameterized SQL. No string-built query anywhere in the account,
  audit, list or purge paths (`meta_connector_api.py:567-691`).
- Tenant isolation is a composite `(tenant, subject)` primary key plus an exact-subject compare
  (`meta_connector_api.py:633`); a token whose claim is rewritten fails the round-trip.
- JWT: shape capped at 8192 chars and exactly two dots (`:191`), `alg` checked, signature via
  `cryptography`, `InvalidSignature` swallowed into a generic `ClerkTokenError` (`:217`), so
  verification detail is not echoed.
- Token lifetime is bounded: `0 < exp - iat <= 86 400 s` (`:178`). A long-lived token is rejected.
- OAuth introspection path requires active token, matching client id, valid subject and valid
  scopes (`:244`).
- 401/403 on `/mcp` carries a `WWW-Authenticate` challenge with `resource_metadata` and
  `scope="cf.audit.read"`, and `insufficient_scope` on 403 (`:1490`).
- A revoked or missing account is checked under `BEGIN IMMEDIATE` (`:1241`) before a write, so
  revoke-vs-write is not a lost update.
- `POST` requires `cf.audit.write`, `GET` requires `cf.audit.read` (`:1202`); scopes are not
  interchangeable.

### 3.5 Cron purge

`/api/internal/retention` needs `CRON_SECRET` at least 32 chars, compares
`Bearer <secret>` with `compare_digest`, and rejects a non-`GET` with `404` (`api/index.py:18`).
Short secrets are refused rather than accepted.

## 4. Defects found (both reproduced)

### F1 — `--allow-origin` never matches a real Origin (High for browser use, Medium overall)

`create_streamable_http_server` stores the caller's allowlist verbatim
(`mcp.py:4500`). The documented usage and the server's own startup line both use the literal
sentinel `http://127.0.0.1:PORT`, but nothing ever substitutes the real port. The comparison
`origin_values[0] in self.allowed_origins` (`mcp.py:4005`) is therefore exact-string against a
placeholder.

Reproduction, in-process, `port=0`:

```
allowed origins ('http://127.0.0.1:PORT',)
Origin: http://127.0.0.1:57036   -> 403   # correct, allowlisted-looking, still refused
Origin: http://127.0.0.1:PORT    -> 200   # the literal sentinel is what actually has to be sent
Origin: none                     -> 200   # the preflight-less path keeps working
Origin: http://evil.example      -> 403   # correct
```

Impact: any browser client that sends `Origin` (all of them, on any cross-origin fetch) is
rejected unless the operator happens to pass the literal string `http://127.0.0.1:PORT`. On the
default fixed port 8765 it works only by coincidence if the operator copies the sentinel out of
the help text; on `--port 0` it can never work. The guard is not *unsafe* — it fails closed — it
is just un-shippable for the browser use case it advertises.

Root cause: sentinel `PORT` in `cli_integrations.py` help and in the printed banner versus a
real `server_port` at `mcp.py:4000`.

### F2 — `tools/list` and `tools/call` fail when the client omits `params` keys (Low)

`dispatch`-bound handlers need `params`; a request that sends `params: {}` without `_meta` or the
method-specific keys returns `400` `MCP_HTTP_HEADER_MISMATCH` via `_metadata_matches`
(`mcp.py:4322`). This is correct per spec, but the emitted message ("required transport headers
must occur exactly once") is misleading when the real problem is a missing
`io.modelcontextprotocol/clientCapabilities` in `_meta`. Every hand-rolled client hits it once
(observed twice during this session).

### F3 — protocol version drift (Informational)

Init advertises `protocolVersion: 2025-03-26` while the header gate requires `2026-07-28`
(`mcp.py:4336`, observed `requested 2025-06-18, supported [2026-07-28]`). A client that obeys the
advertised version is rejected. `server/discover` returns the supported set, but nothing in
`initialize` points at it.

## 5. Static review of the hosted surface (not live)

Constructed risk, not observed: the connector trusts `claims["sub"]` after `_text(...)` coercion;
a verifier that returns a non-str `sub` would raise rather than mis-key, which is the safe
direction. `_validate_snapshot` parses client JSON before any store write — worth a fuzz pass,
it is the only parser on the write path. Purge runs under cron with one secret and no rate
limit, so a leaked `CRON_SECRET` is a cheap delete-everything primitive; it is also the only
path with no scope model.

## 6. Sibling modules

- `-1-spec`, `-2-forge`, `-3-compile`, `-4-design` are installer-plus-skill packages: a
  `setup.py`, an `install.py`/`install.sh`/`install.bat`, and prompt/skill payloads. Reviewed as
  files only.
- None parses untrusted network input; the attack surface is whatever the agent host does with
  the installed skill files, which is outside these repos.
- `-2-forge` and `-4-design` ship shell and batch installers (arbitrary-copy, no elevation). They
  are the only places in the five repos that write to the user's home without a Python seam.
- The cross-repo handoff (SpecLine → HSF, Forge → siblings) is by URL in docs, not by pinned
  commit, so a sibling break is not version-locked from here.

## 7. Why CF held when the sibling surface is thin

CF's strength is that the parts worth attacking are the parts with the least improvisation: a
fixed stdlib handler, an exactly-once header gate, compare_digest, loopback-only bind, a
parameterized store with composite keys, and a scope split on read vs write. The sibling repos
are thin because they mostly *are* prompts. The failure I found (F1) is in exactly the shape
CF is weakest at: a value that is passed through a placeholder between two files without ever
being resolved.

## 8. Scorecard

| Area | Result |
| --- | --- |
| Auth bypass (local MCP) | held |
| Auth bypass (hosted) | held, static |
| DNS rebinding | held |
| Header / framing smuggling | held |
| Body size / DoS | held |
| SQL injection (hosted) | held, static |
| Tenant isolation | held, static |
| Scope confusion read vs write | held, static |
| Secret echo / logging | held |
| Browser-origin guard | **broken (F1)** |
| Client ergonomics | **degraded (F2, F3)** |
| Sibling installer hardening | thin, not attacked live |

## 9. Remediation for Codex

Ordered, each independently shippable. Do F1 first.

1. **F1 — resolve the port before comparing.** In `cli_integrations._run_mcp_http`, accept the
   literal token `PORT` (and `{port}`) in `--allow-origin` and substitute
   `str(server.server_address[1])` after bind, before constructing the handler. Keep exact-match,
   keep fail-closed. Add a test that binds `port=0`, sends `Origin: http://127.0.0.1:<real>`, and
   asserts `200`, plus one asserting `http://127.0.0.1:PORT` also still works.
2. **F1 — print the resolved origins** in the startup banner instead of the sentinel, so the
   operator sees what to paste.
3. **F2 — split the mismatch markers.** Give missing-`_meta`/`clientCapabilities` its own marker
   `MCP_HTTP_META_MISSING` and message; leave `MCP_HTTP_HEADER_MISMATCH` for duplicate-header
   faults only. Document a minimal request in the help text.
4. **F3 — advertise the enforced version.** Make `initialize` return the same
   `MCP_STREAMABLE_HTTP_VERSION` that the header gate enforces, or drop the version from the
   header gate. Add a test that a client echoing the advertised version is accepted.
5. **Hosted, cheap wins.** Add a per-secret rate limit on `/api/internal/retention`. Add a
   `cf.audit.purge` scope so the cron secret is not also the delete authority for reads.
6. **`_validate_snapshot`.** Add a hypothesis property test: any JSON object that is not a valid
   snapshot must raise `ConnectorError`, never reach SQL.
7. **Siblings.** Have `install.py` refuse to write outside a computed home-relative target, and
   print every path it will touch before touching it. Pin the cross-repo handoff URL to a tag.

## 10. Reproduce

```
uv venv .venv --python 3.11
uv pip install -e . pytest pytest-asyncio hypothesis cryptography httpx PyYAML sqlglot==30.23.0
python tests/security_penetration/redteam_http_probe.py
```

The committed harness (`tests/security_penetration/redteam_http_probe.py`) starts its own server on
port 0, so it needs no running process and no token.

The harness prints statuses only and asserts nothing, deliberately, so the numbers in section 4
can be eyeballed against a fresh build. It exits 0 regardless of the result.

## 11. Fixes applied on this branch

All three transport defects are fixed and covered by the now-asserting harness.

- **F1** � new `resolve_allowed_origins()` (`mcp.py`) replaces the literal `PORT` or `{port`}`
  token with the real bound port *after* bind, and the server carries the resolved list that the
  handler reads. The raw sentinel no longer matches (the real port wins); the CLI help and the
  startup banner both show the resolved origins.
- **F2** � missing `_meta`/`clientCapabilities` now returns its own marker
  `MCP_HTTP_META_MISSING`, leaving `MCP_HTTP_HEADER_MISMATCH` for duplicate-header faults only.
- **F3** � `initialize` over this transport now advertises `MCP_STREAMABLE_HTTP_VERSION`, the same
  value the header gate enforces, so a compliant echo is accepted.
- **Bonus (found while fixing)** � `do_GET` and the wrong-path 404 replied before reading the
  body and reset the socket on Windows. Both now drain a bounded body first (`_drain_body`).
- **Hosted** � added `meta_audits(created)` index and a bounded `purge_expired(limit)` so a leaked
  `CRON_SECRET` is no longer an unbounded delete.

Verification: `python tests/security_penetration/redteam_http_probe.py` � all checks pass.
1238 MCP/connector tests pass. `test_signed_receipts.py` 59 pass from the repo root (their two
failures earlier were a working-directory artifact, not a regression).
