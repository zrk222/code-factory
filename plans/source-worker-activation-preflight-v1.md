# Plan: source-worker-activation-preflight-v1
Spec: specs/source-worker-activation-preflight-v1.md
Architect verdict: PASS

## Logical decomposition

1. Define a secret-free activation-policy and claim-validation core.
2. Add deterministic preflight and live-rotation observation.
3. Bind the core to Node credential, hashing, timing, and output adapters.
4. Expose a production command and document provider-neutral activation.
5. Prove failure cases, redaction, non-hollow tests, and release compatibility.

## Tasks

- [ ] T1 | slice=products/agent-cloud/app/runtime | files=products/agent-cloud/app/runtime/sourceWorkerActivation.ts,products/agent-cloud/app/runtime/sourceWorkerActivation.test.ts | verify=`npm run test -- --run runtime/sourceWorkerActivation.test.ts` | implement policy parsing, claim validation, redacted receipts, and bounded rotation decisions
- [ ] T2 | slice=products/agent-cloud/app/runtime | files=products/agent-cloud/app/runtime/sourceWorkerActivationEntrypoint.ts,products/agent-cloud/app/runtime/sourceWorkerActivationEntrypoint.test.ts | verify=`npm run test -- --run runtime/sourceWorkerActivationEntrypoint.test.ts` | bind Node JWT decoding, SHA-256, credential reads, timing, and closed command output
- [ ] T3 | slice=products/agent-cloud/app | files=products/agent-cloud/app/package.json,products/agent-cloud/app/tsconfig.worker.json,products/agent-cloud/app/tsconfig.app.json | verify=`npm run build:source-worker` | expose the activation command in the worker build
- [ ] T4 | slice=docs | files=docs/SOURCE_WORKER_SERVICE.md,docs/AUTHORITATIVE_SOURCE_CONTROL.md | verify=`rg "activation preflight" docs/SOURCE_WORKER_SERVICE.md` | document preflight limits, command behavior, and live rotation procedure
- [ ] T5 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md | verify=`rg "activation preflight" products/agent-cloud/app/README.md` | publish the production activation posture
- [ ] T6 | slice=products/agent-cloud/app | files=products/agent-cloud/app/runtime/sourceWorkerActivation.test.ts,products/agent-cloud/app/runtime/sourceWorkerActivationEntrypoint.test.ts | verify=`npm run test -- --run runtime/sourceWorkerActivation.test.ts runtime/sourceWorkerActivationEntrypoint.test.ts` | prove mismatch, expiry, redaction, rotation, and timeout behavior
- [ ] T7 | slice=products/agent-cloud/app | files=products/agent-cloud/app/runtime/sourceWorkerActivation.test.ts | verify=`npm run verify:enterprise` | prove release and enterprise compatibility
