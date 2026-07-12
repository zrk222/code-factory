# Code Factory Enterprise Vision

This document preserves the long-range enterprise architecture. It is a vision
and fundraising artifact, not the current build plan. The adoption sequence is
developer-first: prove demand for the existing five-brick workflow, ship signed
receipts as the first trust upgrade, and promote later phases only from observed
user and customer needs.

```mermaid
flowchart TB
    SCM["SCM and IDE events"] --> CP["Tenant control plane"]
    CP --> ID["Human and workload identities"]
    CP --> POL["Signed policy bundles"]
    POL --> DAG["Risk-adaptive assurance DAG"]
    DAG --> RUN["Isolated runners"]
    RUN --> REC["DSSE receipt v2 ledger"]
    REC --> GRAPH["Evidence graph"]
    GRAPH --> SUP["SLSA, in-toto, SBOM, and VEX"]
    GRAPH --> OSC["OSCAL assessment results"]
    GRAPH --> PRIV["Merkle, BBS, and zk policy proofs"]
    GRAPH --> PROM["Policy-controlled promotion"]
    PROM --> OPS["Canary, runtime, rollback, and vulnerability receipts"]
    OPS --> GRAPH
```

## Trust rules

- A digest proves content identity, not issuer identity.
- A receipt becomes enterprise evidence only after signature and policy checks.
- Every decision binds the exact policy, subject, tenant, and signer identities.
- Legacy v1 receipts remain readable but cannot satisfy signed-evidence policy.
- Overrides preserve failed gate state and require authenticated, expiring approval.
- Offline verification performs no network calls and needs only the evidence bundle
  plus its trust roots.
- Privacy proofs disclose the minimum claims required by the verifier.

## Eventual delivery order

1. Receipt v2, DSSE, identity, policy, revocation, and offline verification.
2. Tenant control plane, evidence store, SSO/SCIM adapters, authorization, and SCM apps.
3. Assurance graph, adaptive gates, isolated runners, SBOM/VEX, policy mutation,
   and private challenge sets.
4. OpenTelemetry, deployment and rollback evidence, vulnerability response, SIEM,
   and ticketing connectors.
5. OSCAL and versioned NIST SSDF, OWASP ASVS, SOC 2, ISO 27001, and customer packs.
6. Merkle selective disclosure, BBS credentials, and a bounded zkVM policy proof pilot.

None of these phases is represented as shipped by this document. Public claims
must come from released commands, receipts, CI runs, or generated artifacts.
