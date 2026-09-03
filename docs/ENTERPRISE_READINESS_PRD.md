# Enterprise Readiness PRD — Enforced Proof Control Plane

**Status:** proposed — not a claim of certification, managed-service availability,
or customer approval
**Owner:** Code Factory product and platform engineering
**Decision requested:** approve an enterprise-pilot program, then promote only
after the acceptance criteria below are evidenced.

## 1. Executive decision

Code Factory is currently a strong **local, supervised proof layer**. It can
seal intent, preserve rule provenance, reject oracle weakening, bind local
evidence, and show a human a reviewable chain:

`source → obligation → forbidden behavior → gate → test → evidence → decision`

That is valuable enterprise architecture, but it is not by itself an enterprise
product. A local digest is not a workload identity. A local lease is not an
enforcement point. A tenant-shaped database is not a managed availability,
security, or compliance program.

This PRD closes those gaps in a deliberate sequence: first make the proof
chain enforceable at a real execution boundary, then make it tenant-safe and
operable, then make it reviewable by a customer security team. No phase may
claim more than its recorded evidence proves.

## 2. Senior engineering readiness rating

| Area | Current assessment | Pilot target | Enterprise-production target |
| --- | --- | --- | --- |
| Intent and oracle integrity | Strong local foundation | Source-bound contracts and challenge evidence required per run | Signed, policy-versioned contracts retained by tenant |
| Agent authorization | Local typed handoff and expiring receipt | Runner verifies workload identity and lease before every consequential call | Distributed policy enforcement with revocation and audit |
| Evidence | Hash-valid local receipts and offline checks | Signed receipt bundle and isolated execution evidence | Durable tenant evidence ledger, retention, legal hold, export |
| Identity and tenancy | Reference OIDC/RLS lifecycle exists | SSO/RBAC, tenant-scoped keys, audited administrator actions | SAML/SCIM, managed key lifecycle, break-glass controls |
| Operations | Local/supervised tooling | Measured service SLOs, backup/restore exercise, incident runbooks | HA/DR evidence, staffed support commitments, customer-visible status |
| Procurement assurance | Architecture/control mappings | Security questionnaire pack, DPA/subprocessor inventory, SBOM/VEX | Independent assessment/certification only after it is actually achieved |

**Recommendation:** rate the present product **enterprise-pilot worthy for
non-production or supervised customer workloads**, not yet enterprise-
procurement ready. The release gate for the production claim is this PRD's
acceptance evidence—not feature count.

## 3. Problem

Enterprise teams adopting coding agents need to answer six questions that a
green build cannot answer:

1. Which approved source, requirement, and forbidden outcome governed this
   change?
2. Which human and which authenticated workload were allowed to do which exact
   operation, for how long, and under which policy version?
3. Could an agent weaken the test, threshold, exception, or scope after it
   failed?
4. Was the production artifact independently exercised, isolated, and bound to
   the same intent contract?
5. Can one tenant's identity, data, keys, and evidence ever be read or acted on
   by another tenant?
6. Can security, compliance, and engineering reconstruct and revoke the
   decision without trusting an agent's narrative?

Today Code Factory addresses parts of questions 1, 3, and 6 locally. The new
product must answer all six through enforceable, exportable evidence.

## 4. Product goals

1. **Make authority enforceable.** Every consequential runner operation must
   pass a policy enforcement point (PEP) that independently validates the
   tenant, workload identity, contract digest, action, scope, expiry, and
   revocation state.
2. **Make the Oracle chain reviewable.** Preserve the seven-link proof chain in
   a customer-readable dossier and Graph Ops view, including before/after
   semantic diffs for any attempted weakening.
3. **Keep humans in control.** Policy changes, high-risk exceptions, production
   promotion, and autonomy expansion require named human approval. Automation
   may only act inside a short-lived, pre-approved lease.
4. **Separate deterministic and semantic assurance.** Schema/provenance/scope
   checks fail closed deterministically. Independent challenge lanes and human
   review handle the remaining semantic uncertainty. The product must never
   represent one as proof of the other.
5. **Make a security review feasible.** Give customers a clear architecture,
   data-flow inventory, operational evidence, and verifiable exports rather
   than a private vocabulary or unsupported compliance claims.

## 5. Non-goals and claim boundaries

- This program does not claim to prove an LLM's private reasoning, intent,
  semantic truth, or provider-side behavior without corresponding evidence.
- It does not claim eBPF, Envoy, confidential-computing, SLSA, SOC 2, ISO
  27001, HIPAA, or FedRAMP coverage until each is separately implemented and
  independently evidenced.
- It does not replace customer change-management, secure-development, or
  incident-response responsibility.
- It does not introduce autonomous deployment, payment, messaging, identity
  administration, or credential handling by default.

## 6. Users and jobs

| User | Job | Successful outcome |
| --- | --- | --- |
| Senior engineer | Let an agent make a bounded change without accepting an unverifiable story | A sealed contract, independent challenge result, and exact diff are visible before review |
| Engineering manager | Allow more automation without lowering code-review standards | Autonomy is earned per repository, scoped, expiring, and automatically demoted on a violation |
| Security engineer | Review agent risk without learning proprietary product language | Exportable policy, identity, action, evidence, revocation, and incident records map to familiar controls |
| Compliance/auditor | Reconstruct a decision months later | Tenant-scoped, signed and retained evidence verifies offline against documented trust roots |
| Platform operator | Stop an unsafe or compromised run quickly | Revoke workload identity/lease/policy and observe fail-closed enforcement within a recorded target |

## 7. Product requirements

### EP-1 — Workload identity and continuous authorization

The hosted runner shall obtain a short-lived workload identity from a supported
customer or Code Factory identity issuer. It shall not accept a user-supplied
`agent` field as identity proof.

- Bind every high-risk action to `tenant_id`, `workload_id`, `contract_digest`,
  `policy_digest`, `lease_digest`, action, scope, expiry, and correlation id.
- Validate identity signature, issuer, audience, expiry, tenant, and revocation
  before the PEP permits the action.
- Enforce least privilege: a lease can only narrow the already approved Oracle
  contract; it cannot add scope, actions, sources, exceptions, or thresholds.
- Require replay protection and a monotonic decision record for every admitted
  consequential action.
- Fail closed if the PEP, time source, policy, identity, or revocation check is
  unavailable or contradictory.

**Acceptance evidence:** integration tests prove expired, revoked, wrong-
tenant, wrong-audience, wrong-scope, duplicate-id, and policy-digest-mismatch
requests are denied before the runner receives an executable command.

### EP-2 — Policy decision and enforcement architecture

Deliver a policy decision point (PDP) and a runner-adjacent PEP. The PEP is the
only path to tools classified as consequential.

- Classify actions as `read`, `test`, `repair`, `merge`, `deploy`, `publish`,
  `credential`, `message`, and `purchase`; defaults must deny unclassified
  actions.
- Permit only `read` and bounded local `test` actions in an unleased developer
  environment. All other actions require an active lease and risk policy.
- Log both allow and deny decisions with policy and contract digests, never raw
  secrets or source bodies.
- Keep a local developer mode, but label it *supervised local* and prevent it
  from being represented as hosted enforcement.

**Acceptance evidence:** a topology test proves no registered runner/tool
adapter can bypass the PEP; mutation tests kill an attempted direct invocation
or allowlist widening.

### EP-3 — Tenant isolation, access, and keys

Build the control plane as a tenant-safe service rather than a collection of
tenant-labelled receipts.

- Support OIDC first; add SAML SSO and SCIM provisioning after the pilot.
- Enforce tenant identifiers in the authorization layer and database RLS,
  including background jobs, exports, queues, and object storage paths.
- Store keys and secrets in a reviewed KMS/HSM-backed interface. The service
  stores references, not secret material.
- Provide administrator, security reviewer, developer, auditor, and break-
  glass roles with separate least-privilege capabilities.
- Make break-glass time limited, dual-audited, and alert-producing.

**Acceptance evidence:** cross-tenant negative tests cover API, worker,
storage, export, restore, and background-job paths; a key-rotation rehearsal
verifies prior evidence without retaining active signing authority.

### EP-4 — Durable evidence, provenance, and export

Create a tenant-scoped evidence ledger for the seven-link proof chain.

- Sign receipt envelopes using an enterprise-managed signing policy; publish
  verification material and rotation/revocation metadata.
- Retain immutable links among source hashes, contract versions, policy,
  handoffs, leases, PEP decisions, runner attestations, test/challenge results,
  artifact hashes, and human decisions.
- Support bounded retention, legal hold, customer export, and offline
  verification. Exports must redact secrets, raw prompts, and source contents
  unless the customer explicitly opts into including them.
- Emit structured events compatible with customer SIEM ingestion and preserve
  correlation ids across runner, control plane, and reviewer views.

**Acceptance evidence:** an independently executed verifier accepts an intact
export and rejects altered receipt, expired/revoked signer, wrong-tenant
bundle, and broken evidence edge.

### EP-5 — Independent execution and challenge lane

Strengthen the difference between “test passed” and “behavior proved.”

- Run challenge jobs in an isolated environment with documented filesystem,
  network, resource, image, and egress policy.
- Generate boundary and counterfactual cases from the sealed contract, not from
  the worker's edited test alone.
- Fail closed on oracle weakening: tolerance widening, removed required case,
  deleted negative test, new exception, reclassified defect, or post-failure
  threshold reduction produces `E_ORACLE_WEAKENING` and an incident capsule.
- Bind SBOM, dependency/vulnerability findings, artifact attestation, and
  deployment candidate identity to the same contract where those integrations
  are enabled.

**Acceptance evidence:** a red-team fixture demonstrates that a hollow test,
scope escape, policy weakening, and artifact substitution cannot produce an
eligible promotion record.

### EP-6 — Human control and Graph Ops

Graph Ops becomes the review console, not a control bypass.

- Display the full proof chain as separate navigable nodes: source,
  obligation, forbidden behavior, gate, test, evidence, decision.
- Surface known facts, blocking unknowns, uncertainties, capability limits,
  sensitivity signals, lease expiry, revocation, and attempted exceptions.
- Require named, contextual approval for policy successor, exception, autonomy
  expansion, and production promotion. No page button may silently authorize
  an external action.
- Produce a review dossier with “proved”, “observed”, “declared”, “unknown”,
  and “not checked” classifications—not a single misleading green score.

**Acceptance evidence:** usability tests show a reviewer can locate the exact
source and evidence behind a decision; access-control tests prove read-only
views cannot write policy or admit work.

### EP-7 — Operability and customer assurance

Prepare the system to be operated, supported, and reviewed.

- Define service boundaries, SLOs, error budgets, backup/restore objectives,
  DR targets, incident severity model, vulnerability response, and status
  communication.
- Instrument control-plane and runner health with privacy-safe telemetry;
  document data classification, retention, residency choices, and deletion.
- Maintain a customer security package: architecture diagram, threat model,
  pen-test status, SBOM/VEX policy, DPA/subprocessor inventory, access-control
  model, incident process, and roadmap claims table.
- Do not sell a contractual SLA or certification before staffing, process,
  measurement, and legal commitments are actually in place.

**Acceptance evidence:** restore and incident exercises have dated receipts;
the security package is generated from versioned evidence and reviewed by a
qualified external party before customer assertions are made.

## 8. Delivery sequence and release gates

| Phase | Scope | Exit gate | Explicitly not claimed |
| --- | --- | --- | --- |
| 0 — Architecture freeze | Threat model, action taxonomy, data flow, policy model, customer pilot design | Senior architecture review approves the boundaries and abuse cases | Production enforcement |
| 1 — Enforced pilot | OIDC workload identity, PEP/PDP, lease/revocation checks, signed receipts, one isolated runner integration | Red-team and integration fixtures show bypass/expiry/replay/cross-tenant denial | Managed HA, SAML/SCIM, certifications |
| 2 — Tenant operations | Tenant lifecycle, key references/rotation, evidence export/retention, SIEM events, Graph Ops dossiers | Tenant isolation, export verification, restore exercise, operational SLO telemetry | Contractual SLA or broad standards compliance |
| 3 — Procurement readiness | SAML/SCIM, customer security package, external testing, support runbooks, DR drill | Customer-design-partner security review closes high findings | SOC 2/ISO certification unless completed independently |
| 4 — Production enterprise | Multi-region/DR as justified, managed support, additional SCM/runner integrations, compliance attestations where earned | Signed release readiness decision with external evidence | Universal proof of agent correctness |

## 9. Metrics and decision rules

Metrics are decision inputs, not marketing claims:

- PEP coverage: proportion of consequential registered actions that have no
  direct execution path outside PEP.
- Deny integrity: proportion of seeded invalid authorization scenarios denied
  before tool dispatch.
- Oracle integrity: count and classification of weakening attempts caught,
  reviewed, and resolved; never present this as an agent-quality score alone.
- Evidence completeness: proportion of eligible decisions with all seven proof
  links and a verifiable signing/retention state.
- Isolation/tenant tests: pass rate of cross-tenant, restore, revocation, and
  policy-mutation negative fixtures.
- Operations: observed availability, recovery exercises, decision latency,
  and security response time against stated SLOs.
- Adoption: time from a sealed contract to a reviewer-readable dossier and
  percentage of pilots that complete a governed workflow without bypass.

Any missing high-risk proof link, PEP bypass, tenant-boundary failure, failed
replay/revocation test, or unresolved critical security finding blocks
promotion to the next phase.

## 10. Key risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Static policy validates a harmful but well-formed request | Keep independent challenge lane and human decision; state semantic limits plainly |
| PEP becomes a single point of failure | Fail closed for consequential actions; design availability/DR before promising managed execution |
| Provider exports are forged or incomplete | Treat them as declared evidence until bound to authenticated workload, local artifacts, and independent checks |
| Evidence ledger leaks prompts, code, or secrets | Default to hashes and allowlisted metadata; apply explicit customer-controlled export policy |
| Over-scoping into compliance theater | Map controls to evidence and use “not yet” labels until an independent assessment exists |
| Developer friction causes bypass | Keep local read/test flows fast, make policy denial actionable, and measure bypass pressure in design-partner pilots |

## 11. Open decisions required before Phase 1

1. Initial deployment model: customer-managed, single-tenant hosted, or shared
   hosted control plane with an isolated runner per tenant.
2. Initial identity standard: customer OIDC only, or a platform broker with
   documented federation and key ownership.
3. Initial consequential action set and the exact actions permanently prohibited
   in the first pilot.
4. Evidence residency, retention, and customer export requirements.
5. Whether pilot customers require an on-premise/offline verifier from day one.
6. Security budget and named owner for threat modeling, external testing,
   incident response, and privacy/legal review.

## 12. Definition of done

This PRD is done when a designated pilot customer can use a governed agent
workflow and independently verify: who was authorized, what contract bound the
work, what the agent was forbidden to do, which deterministic checks occurred,
what independent evidence was produced, what remained unknown, and which named
human made the final decision—without trusting Code Factory's prose alone.
