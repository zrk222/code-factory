# Plan: source-worker-service-v1
Spec: specs/source-worker-service-v1.md
Architect verdict: PASS

## Logical decomposition

1. Extract deterministic service state and scheduling behavior.
2. Add authenticated Convex and HTTPS alert process adapters.
3. Package a non-root container and hardened orchestration template.
4. Publish an honest activation runbook.
5. Prove worker and enterprise release behavior.

## Tasks

- [ ] T1 | slice=products/agent-cloud/app/runtime | files=products/agent-cloud/app/runtime/sourceWorkerService.ts,products/agent-cloud/app/runtime/sourceWorkerService.test.ts | verify=`npm run test -- --run runtime/sourceWorkerService.test.ts` | implement config, non-overlap, retry, readiness, and drain contracts
- [ ] T2 | slice=products/agent-cloud/app | files=products/agent-cloud/app/runtime/sourceWorkerEntrypoint.ts,products/agent-cloud/app/tsconfig.worker.json | verify=`npm run build:source-worker` | implement Convex, HTTPS, scheduling, health, alert, and signal adapters
- [ ] T3 | slice=products/agent-cloud/app | files=products/agent-cloud/app/Dockerfile.source-worker,products/agent-cloud/app/deploy/source-worker/kubernetes.template.yaml | verify=`rg "runAsNonRoot: true" products/agent-cloud/app/deploy/source-worker/kubernetes.template.yaml` | package non-root container and hardened deployment template
- [ ] T4 | slice=docs | files=docs/SOURCE_WORKER_SERVICE.md,docs/AUTHORITATIVE_SOURCE_CONTROL.md | verify=`rg "activation required" docs/SOURCE_WORKER_SERVICE.md docs/AUTHORITATIVE_SOURCE_CONTROL.md` | document configuration, probes, secret boundaries, and activation limits
- [ ] T5 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md | verify=`rg "activation required" products/agent-cloud/app/README.md` | publish the worker posture in the application guide
- [ ] T6 | slice=products/agent-cloud/app | files=products/agent-cloud/app/runtime/sourceWorkerService.test.ts | verify=`npm run verify:enterprise` | prove service and enterprise release behavior
