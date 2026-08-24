# Plan: agent-oven-render-local-port-v1
Spec: specs/agent-oven-render-local-port-v1.md
Architect verdict: PASS

## Logical decomposition

1. Lock local development and preview to loopback port 6668.
2. Add a static Render Blueprint with dashboard-supplied browser configuration.
3. Document local and Render activation boundaries.
4. Prove fixed-port HTTP behavior, strict fallback rejection, and Blueprint structure.

## Tasks

- [ ] T1 | slice=products/agent-cloud/app | files=products/agent-cloud/app/vite.config.ts | verify=`node node_modules/vite/bin/vite.js --host 127.0.0.1` | configure fixed loopback development and preview servers
- [ ] T2 | slice=render.yaml | files=render.yaml | verify=`render blueprints validate` | define the secret-free Render static-site Blueprint
- [ ] T3 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md | verify=`rg "127.0.0.1:6668" products/agent-cloud/app/README.md` | document local and Render setup boundaries
- [ ] T4 | slice=products/agent-cloud/app | files=products/agent-cloud/app/vite.config.ts | verify=`curl.exe -I http://127.0.0.1:6670/` | prove the fixed port serves HTTP 200
- [ ] T5 | slice=render.yaml | files=render.yaml | verify=`rg "sync: false" render.yaml` | prove browser configuration remains dashboard supplied
