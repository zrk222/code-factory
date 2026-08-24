# Spec: agent-oven-render-local-port-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Agent Oven shall serve local development and preview traffic only on browser-safe loopback port 6670 without silent fallback, and shall provide a secret-free Render Blueprint for the static web application.

### Requirements (EARS)

- When `LOCAL_DEVELOPMENT_STARTS` occurs, Vite shall return a listening development server at `127.0.0.1:6670`.
- When `LOCAL_PREVIEW_STARTS` occurs, Vite shall return a listening preview server at `127.0.0.1:6670`.
- If `LOCAL_PORT_OCCUPIED` means TCP port `6670` is unavailable, Vite shall reject startup instead of selecting another port.
- When `LOCAL_HTTP_SMOKE_RUNS` performs an HTTP GET against `http://127.0.0.1:6670/`, the running development server shall return status `200`.
- While `RENDER_STATIC_BLUEPRINT_EXISTS` is checked, `render.yaml` shall define one static web service rooted at `products/agent-cloud/app`, publish `dist`, and rewrite `/*` to `/index.html`.
- While `RENDER_BROWSER_CONFIGURATION_REQUIRED` is checked, the Blueprint shall declare `VITE_CONVEX_URL`, `VITE_AUTH0_DOMAIN`, and `VITE_AUTH0_CLIENT_ID` with `sync: false` and shall contain no credential value.
- While `RENDER_WORKER_IDENTITY_UNAVAILABLE` means projected workload identity and CSI-mounted secrets are unavailable, the Blueprint shall omit the authoritative-source worker service.
- If `RENDER_ACCOUNT_AUTHENTICATION_MISSING` occurs, documentation shall return a Render Blueprint dashboard link and shall not claim a live deployment.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Local Agent Oven is reachable on its fixed port
  Given TCP port 6670 is free
  When the Vite development server starts
  Then an HTTP GET to http://127.0.0.1:6670/ returns status 200
  And Vite does not listen on port 5173

Scenario: Render receives a secret-free static-site contract
  Given the repository Blueprint
  When Render evaluates the Agent Oven service
  Then it builds products/agent-cloud/app
  And it publishes the dist directory
  And all three browser configuration values require dashboard entry
```

## SHOULD - Technical and structural

- Keep port configuration centralized in `vite.config.ts`.
- Use Render static hosting rather than a permanent Vite preview process.
- Include SPA routing and browser security headers in the Blueprint.

## SHOULD NOT - Implementation details

- Do not bind the local server to a public interface.
- Do not place Auth0, Convex, worker, or connector secrets in `render.yaml`.
- Do not deploy the source worker to a host that cannot satisfy its identity and secret-mount contract.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `LOCAL_DEVELOPMENT_STARTS` | bind `127.0.0.1:6670` |
| 2 | `LOCAL_PREVIEW_STARTS` | bind `127.0.0.1:6670` |
| 3 | `LOCAL_PORT_OCCUPIED` | reject startup |
| 4 | `LOCAL_HTTP_SMOKE_RUNS` | return HTTP 200 |
| 5 | `RENDER_STATIC_BLUEPRINT_EXISTS` | return one static web service |
| 6 | `RENDER_BROWSER_CONFIGURATION_REQUIRED` | require three unsynchronized values |
| 7 | `RENDER_WORKER_IDENTITY_UNAVAILABLE` | omit the worker service |
| 8 | `RENDER_ACCOUNT_AUTHENTICATION_MISSING` | return a dashboard handoff without a live claim |
