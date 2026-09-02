# Enterprise Enforcement Reference

Code Factory now has a deterministic **enterprise admission reference**. It is
the local Phase 1 foundation for the enterprise roadmap, not a hosted security
product or an approval claim.

## What it checks

For one proposed operation, the reference verifies all of the following before
it records an admission receipt:

1. A signed workload identity is current, has the exact tenant, workload,
   subject, audience, and action class, and expires within 24 hours.
2. A separately signed tenant policy permits the exact action class and paths.
3. An optional signed revocation list has not revoked that workload identity.
4. When policy requires it, a current semantic lease binds the same agent,
   context, action, scope, and sealed Oracle Contract.
5. A repeated action ID cannot receive a second immutable decision receipt.

The visible proof chain is:

`source → obligation → forbidden behavior → gate → test → evidence → decision`

The Oracle Contract anchors the first five links; this admission receipt is the
final decision link. A green test alone cannot replace any of them.

## What it does not claim

This module is intentionally local and offline. It **does not** authenticate a
real cloud workload through OIDC federation, execute a command, call a tool,
prove a sandbox, control an Envoy/eBPF policy point, issue a credential, or
approve/publish/deploy a release. A production pilot must wire the separate
runner's only consequential route through a PEP and prove that topology.

## Local reference workflow

```powershell
# 1. Create development-only Ed25519 material and explicit local trust root.
factory enterprise keygen --out-dir .factory/enterprise-keys --keyid ci-proof `
  --identity https://example.invalid/proof --issuer https://issuer.example.invalid

# 2. Sign a workload identity and a tenant policy from reviewed JSON input.
factory enterprise workload-identity-seal identity.json --private-key .factory/enterprise-keys/ci-proof.private.pem `
  --keyid ci-proof --identity https://example.invalid/proof --issuer https://issuer.example.invalid --out identity.dsse.json
factory enterprise enforcement-policy-seal policy.json --private-key .factory/enterprise-keys/ci-proof.private.pem `
  --keyid ci-proof --identity https://example.invalid/proof --issuer https://issuer.example.invalid --out policy.dsse.json

# 3. Record a non-executing decision. The separate runner must verify this
#    receipt itself before it can do any consequential work.
factory enterprise authorize request.json --root . --workload-identity identity.dsse.json `
  --policy policy.dsse.json --trust-root .factory/enterprise-keys/trust-root.json `
  --out .factory/enterprise-enforcement/decisions/restore-test.json
```

The command returns `ENTERPRISE_PEP_REFERENCE_ADMITTED` only for a matching
identity, policy, scope, action, and (when required) semantic lease. Every
returned decision sets every authority flag to `false`.

## Pilot exit criteria

Before calling this an enterprise production control, demonstrate all of these
outside the local reference:

- OIDC workload federation with tenant-isolated key and revocation management.
- A runner topology where the PEP is the only route to consequential tools.
- Independent challenge execution in an isolated environment.
- Red-team proof that cross-tenant, expired, replayed, revoked, scope-expanded,
  and policy-bypassing requests are denied at the real enforcement point.
- Auditable export/retention, operator alerts, recovery exercises, support,
  security review, and contractual evidence required by the buyer.

Until those receipts exist, use the module as an evidence-backed local
reference and pilot artifact—not as a substitute for a security review.
