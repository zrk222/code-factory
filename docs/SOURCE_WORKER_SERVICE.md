# Source Worker Service

## What is operable now

The authoritative-source worker is a standalone Node service. It obtains credential-free, digest-pinned source definitions from Convex; resolves an opaque endpoint reference inside the worker boundary; performs bounded HTTPS probes; records content-free observations; and posts metadata-only alerts. It exposes process liveness at `/healthz` and source-monitoring readiness at `/readyz`.

This is a supervised runtime component. The repository contains the service, tests, container recipe, and orchestration template. Its production posture remains **credential activation required** until a real environment supplies a trusted issuer and audience, service-identity membership, a vault CSI provider, a digest-pinned image, alert routing, and independently scheduled replicas.

## Configuration

| Variable | Required | Contract |
|---|---:|---|
| `CONVEX_URL` | Yes | HTTPS deployment URL |
| `SOURCE_WORKER_AGENT_SPEC_ID` | Yes | Agent whose source definitions are monitored |
| `SOURCE_WORKER_OIDC_TOKEN_FILE` | Production | Absolute path to a projected rotating OIDC token; reread before every cycle |
| `SOURCE_WORKER_OIDC_TOKEN` | Development only | Static opaque token; mutually exclusive with the token-file setting |
| `SOURCE_WORKER_VAULT_MOUNT` | For `vault:` references | Absolute root of the secret-store CSI mount |
| `SOURCE_WORKER_POLL_SECONDS` | No | Integer 15 through 86400; default 60 |
| `SOURCE_WORKER_HEALTH_PORT` | No | Integer 1024 through 65535; default 8080 |
| `SOURCE_WORKER_ALERT_WEBHOOK_URL` | No | HTTPS webhook receiving code, counts, and occurrence time only |
| `SOURCE_WORKER_EXPECTED_ISSUER` | Activation | Exact workload-token issuer, 1 through 512 characters |
| `SOURCE_WORKER_EXPECTED_AUDIENCE` | Activation | Exact Convex workload audience, 1 through 512 characters |
| `SOURCE_WORKER_EXPECTED_SUBJECT` | Activation | Exact platform service-identity subject, 1 through 512 characters |
| `SOURCE_WORKER_ACTIVATION_REFERENCES` | Activation | JSON array containing 1 through 32 closed `env:` or `vault:` references |
| `SOURCE_WORKER_ROTATION_DRILL_SECONDS` | Rotation drill only | Integer 5 through 300; omission runs one preflight instead of a drill |

The resolver accepts only `env:SOURCE_ENDPOINT_NAME` and `vault:safe/nested/key`. The closed environment namespace prevents a source record from reading worker identity, alert, or unrelated process variables; permitted endpoint values are reread rather than cached. Vault keys allow at most eight closed-alphabet path segments while rejecting traversal, backslashes, and empty or dot-only segments. The Node adapter resolves real paths, proves the target remains below `SOURCE_WORKER_VAULT_MOUNT`, requires a regular file no larger than 64 KiB, and rejects world-readable files outside Windows.

## Build and run

```powershell
npm run build:source-worker
npm run start:source-worker
npm run verify:source-worker-activation
```

Build the container with `Dockerfile.source-worker`. Before applying `deploy/source-worker/kubernetes.template.yaml`, replace the image, OIDC audience, secret-store CSI driver, and SecretProviderClass placeholders. Create the referenced ConfigMap, alert Secret, service account, and provider-specific workload-identity binding through the deployment platform. Do not commit rendered secrets.

## Activation preflight

Run `npm run verify:source-worker-activation` inside the rendered worker environment before enabling source polling. The command requires rotating-file identity, parses the projected JWT claims, requires exact issuer/audience/subject matches, requires at least 120 seconds of remaining token lifetime, and resolves every configured closed source reference. It emits one redacted JSON receipt on success or one closed error code on failure.

The preflight deliberately reports `signatureVerified: false` and `requiresControlPlaneVerification: true`. Decoding claims is not authentication: Convex must still validate the signature, trusted issuer, audience, and service membership. The receipt contains no token, claims, source references, resolved values, mount paths, or fingerprints.

To execute a live rotation drill, set `SOURCE_WORKER_ROTATION_DRILL_SECONDS` from 5 through 300 and run the same command while the platform rotates both the projected service-account token and every configured source secret. The command samples once per second and succeeds only after both identity and all reference values change. A timeout returns `E_SOURCE_WORKER_ROTATION_NOT_OBSERVED` without a receipt.

## Runtime behavior

- A cycle starts immediately and then on the configured interval.
- The identity token is reread and applied before each cycle reaches Convex.
- Overlapping ticks are skipped; the service core rejects direct overlap.
- Source requests use a ten-second timeout, a 2 MiB ceiling, and bounded retry.
- Alert delivery uses at most three attempts with 250 ms and 1000 ms backoff.
- Alert failure is visible as `E_SOURCE_WORKER_ALERT_FAILED` but never replaces the source result.
- Readiness requires a fully successful cycle in the previous three polling intervals.
- SIGTERM and SIGINT stop scheduling and allow ten seconds for the current cycle to drain.

## Activation gates

1. Configure Convex OIDC to trust the workload issuer and exact audience used by the projected token.
2. Provision the service identity as a least-privilege operator member authorized only for definition reads and observation writes.
3. Bind the platform workload identity and install an Azure Key Vault, AWS Secrets Manager, GCP Secret Manager, or compatible CSI/External Secrets provider.
4. Use 0440 or stricter mounted-file permissions and keep source endpoint/licence values inside the CSI mount.
5. Build, scan, sign, and deploy an immutable image digest.
6. Run two replicas across independent failure domains; rotate the projected identity and a vault value while both remain live.
7. Run the activation preflight, then verify identity/source-secret rotation, expired-token, wrong-audience, mount escape, oversized-secret, credential-revocation, stale-source, and alert-failure drills.
8. Monitor the worker from a separate system and retain measured SLO evidence.

The checked-in template deliberately does not create credentials or assert that these gates have been completed.
