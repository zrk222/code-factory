# Plan: source-worker-credential-rotation-v1
Spec: specs/source-worker-credential-rotation-v1.md
Architect verdict: PASS

## Logical decomposition

1. Define secret-free identity and reference contracts.
2. Bind rotating token and confined filesystem adapters to the worker.
3. Replace static-token deployment wiring with projected workload identity.
4. Document issuer, audience, membership, CSI, and rotation activation.
5. Prove rotation, confinement, redaction, and release behavior.

## Tasks

- [ ] T1 | slice=products/agent-cloud/app/runtime | files=products/agent-cloud/app/runtime/sourceWorkerCredentials.ts,products/agent-cloud/app/runtime/sourceWorkerCredentials.test.ts,products/agent-cloud/app/runtime/sourceWorkerNodeSecrets.ts,products/agent-cloud/app/runtime/sourceWorkerNodeSecrets.test.ts | verify=`npm run test -- --run runtime/sourceWorkerCredentials.test.ts runtime/sourceWorkerNodeSecrets.test.ts` | implement rotating identity, closed references, and confined file adapters
- [ ] T2 | slice=products/agent-cloud/app/runtime | files=products/agent-cloud/app/runtime/sourceAssurance.ts,products/agent-cloud/app/runtime/sourceAssurance.test.ts | verify=`npm run test -- --run runtime/sourceAssurance.test.ts` | apply the closed reference contract during authoritative-source admission
- [ ] T3 | slice=products/agent-cloud/app/runtime | files=products/agent-cloud/app/runtime/sourceWorkerEntrypoint.ts,products/agent-cloud/app/runtime/sourceWorkerService.ts,products/agent-cloud/app/runtime/sourceWorkerService.test.ts | verify=`npm run test -- --run runtime/sourceWorkerCredentials.test.ts runtime/sourceWorkerService.test.ts` | bind fresh identity before each cycle and install confined file adapters
- [ ] T4 | slice=products/agent-cloud/app | files=products/agent-cloud/app/deploy/source-worker/kubernetes.template.yaml,products/agent-cloud/app/tsconfig.worker.json | verify=`rg "SOURCE_WORKER_OIDC_TOKEN_FILE" products/agent-cloud/app/deploy/source-worker/kubernetes.template.yaml` | configure bounded projected workload identity
- [ ] T5 | slice=docs | files=docs/SOURCE_WORKER_SERVICE.md,docs/AUTHORITATIVE_SOURCE_CONTROL.md | verify=`rg "credential activation required" docs/SOURCE_WORKER_SERVICE.md` | document trust activation and rotation drills
- [ ] T6 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md,products/agent-cloud/app/src/components/SourceAssurancePanel.tsx,products/agent-cloud/app/convex/authoritativeSources.test.ts | verify=`rg "rotating workload identity" products/agent-cloud/app/README.md` | publish the credential posture and safe endpoint-reference namespace
- [ ] T7 | slice=products/agent-cloud/app | files=products/agent-cloud/app/runtime/sourceWorkerCredentials.test.ts | verify=`npm run verify:enterprise` | prove worker credentials and enterprise release behavior
