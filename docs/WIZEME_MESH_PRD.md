# WizeMe Mesh — Product Requirements Document
## Premium governance, provenance, and proof control plane for AI agent memory

**Document status:** build specification for Codex
**Version:** 4.0 — source-verified reuse
**Reuse baseline:** code-factory @ `4b8b19c098dc61c8451f9ef701861fc807ff7a03` (full suite: 285 passed, 2 skipped)
**Governing invariant:** receipts stay ahead of claims — no capability is described as present until its exit evidence exists

> **Codex: read §0, §1, §4, §5 and §20 in full before writing any code.**
> §4 is the **source-verified** reuse map — a substantial part of this system already exists and passes tests. Do not rebuild anything tagged PORTABLE. §5 is the receipts-authoritative rule, which constrains every integration you write. §19 is the prohibited-actions list.
> **Commit this document into the repository** so future runs can redline it directly. The previous review could not, because it lived outside the checkout.

---

## 0. What this product is and is not

WizeMe Mesh is **not a memory store.** It does not compete with Mem0, Zep, or Letta on retrieval quality. That capability is commoditizing.

Mesh is the **control plane above whatever store an agent uses**, doing three things no store-that-is-also-a-vendor can neutrally do:

1. **Authorize** every consequential memory operation against principal, tenant, purpose, and policy → allow / verify / deny.
2. **Record** that operation as durable, signed, hash-chained evidence that outlives it and exports to an auditor.
3. **Prove** why a memory influenced an agent action — portably, across vendors, locked to none.

The buyer is a team deploying AI agents against data someone can be sued over. Their unmet need is not better recall; it is proving, after the fact, that an agent was permitted to act on a memory and showing exactly what it did.

> **Portable, enforceable proof of how information crossed memory systems and influenced an agent action.**

**Out of scope.** Do not build embedding generation, vector indexing, retrieval ranking, summarization, chunking, model inference, or any storage engine holding memory content as a primary feature.

---

## 1. Claim boundary (Milestone 0)

Reproduce unchanged in `CLAIMS.md`, at module boundaries, in generated docs, in the README, and in investor material. **Never round a label upward, and never drop the domain qualifier.**

| Component | Label |
|---|---|
| Canonical JSON + digest primitives | **BUILT-PROVEN in build domain / UNPROVEN in memory domain** |
| DSSE / Ed25519 receipt signing | **BUILT-PROVEN in build domain / UNPROVEN in memory domain** |
| Offline verification, policy binding, revocation | **BUILT-PROVEN in build domain / UNPROVEN in memory domain** |
| Hosted PostgreSQL tenant isolation (forced RLS) | **BUILT-PROVEN for PR assurance / UNPROVEN for memory** |
| Atomic decision + outbox transaction | **BUILT-PROVEN for PR assurance / UNPROVEN at memory hot path** |
| Hosted OIDC/JWKS authentication | **BUILT-PROVEN for PR assurance / UNPROVEN for Mesh identity lifecycle** |
| Single-account memory governance (WizeMe) | **BUILT-UNPROVEN** |
| Retrieval / evaluation harness (WizeMe) | **BUILT-UNPROVEN** |
| Memory record authority | **CLAIMED-UNBUILT** |
| Purpose binding | **CLAIMED-UNBUILT** |
| Crypto-shredding / erasure | **CLAIMED-UNBUILT** |
| External anchoring | **CLAIMED-UNBUILT** |
| Productized Memory CI | **CLAIMED-UNBUILT** |
| Vendor-neutral enforcement gateway | **CLAIMED-UNBUILT** |

**A component proven in the build domain is not thereby proven in the memory domain.** The qualifier is part of the label. Advancing a label without its exit evidence (§12) is the single prohibited action in this project.

---

## 2. Definitions

| Term | Definition |
|---|---|
| **Principal** | An identity that can act: `human`, `agent`, or `service`. Stable ID, type, home tenant. |
| **Acting-as** | The principal chain for one operation (`agent:X acting-as human:Y`). Depth ≤ 3, recorded whole. |
| **Authority** | The grant permitting this operation, by grant ID. Absence is a deny, never a default-allow. |
| **Tenant** | The isolation boundary. Enforced by construction (row-level security), not by application filter. |
| **Purpose** | A declared, bounded reason. Policies bind to purposes. Mismatch is a deny. Carries a version. |
| **Consequential operation** | Memory write, update, deletion, grant issuance/revocation, approval, policy change, or externally-visible action. Requires atomic evidence (§6). |
| **Sensitive read** | A read of policy-classified sensitive memory. Requires a durable access receipt accepted **before** release. |
| **Telemetry** | Diagnostics and performance data. Best-effort. **Never** compliance evidence; structurally excluded from `prove`/`verify`. |
| **Receipt** | A signed, chained, verifiable record of one decision or operation. The core artifact (§7). |
| **Anchor** | A periodic external commitment to chain state, outside the mutable operational store (§10). |

---

## 3. Existing WizeMe architecture

Codex must verify against the actual repository and report discrepancies.

**Reusable:** governance gates (consent, explicit intent, provenance, sensitivity, audience, purpose, retention, deletion, release decisions) — reuse the decision logic. Provenance/lineage concepts. Account isolation. The evaluation harness.

**Missing:** multi-principal model — account ownership is the only authorization boundary today; audience and purpose are policy *inputs*, not enforceable principal→resource grants. **The audit writer fails open when its latency circuit trips**, silently dropping evidence under load — disqualifying, and the gating fix. Tamper evidence — hashes exist but are not chained, signed, access-controlled, or anchored.

---

## 4. Source-verified reuse map — code-factory

**This table is source-verified**, not inferred from documentation. Citations are `file:line` at the reviewed commit. Codex must confirm against the checkout and report drift.

| Surface | Source | Tag | Boundary that must remain explicit |
|---|---|---|---|
| Canonical JSON + SHA-256 digests | `enterprise_receipts.py:52-61`, `control_plane.py:63-73` | **PORTABLE** | Version-pin the canonicalization contract. A digest proves bytes, not issuer identity. |
| DSSE / Ed25519 signing | `enterprise_receipts.py:193-215` | **PORTABLE** | Key custody and signer authorization are deployment responsibilities; the local private-key loader is not a managed KMS. |
| Offline verification, policy binding, revocation | `enterprise_receipts.py:224-255, 275-311` | **PORTABLE** | Provides no transparency-log inclusion, trusted timestamping, or key lifecycle. Those remain NEW. |
| Trace verification + in-toto/SLSA export | `proof.py:398-461` | **PORTABLE** | Exports **unsigned** statements. Not an anchor, not a transparency-log entry, not issuer-authenticated. |
| Policy mutation gate | `assurance.py:329-345, 348-390` | **PORTABLE** | Adds no purpose binding or memory authorization semantics. |
| MCP starter generator | `target_compiler.py:531-620`, `cli.py:747-785` | **PORTABLE** | The generated server is a starter. A governed MCP surface exposes only receipt-backed operations. |
| Local tenant-scoped evidence, roles, approvals, audit chain | `control_plane.py:35-90, 92-151, 208-225, 304-370` | **ADAPT** | `Principal` has subject/tenant/roles but **no purpose**. SQLite store is a reference implementation. Authorization depends on a trusted identity adapter. |
| Hosted PostgreSQL tenant isolation (forced RLS) | `hosted_storage.py:33-100, 130-153` | **ADAPT** | Schema is PR-delivery/approval-specific and must be generalized before serving memory mutations. |
| Atomic decision + publication outbox | `hosted_storage.py:243-322` | **ADAPT** | Decision, OIDC-use record, and Check outbox row commit in one transaction. **The hot-path guarantee has not been demonstrated for memory writes.** |
| Concurrent outbox delivery + retry | `hosted_storage.py:324-387` | **ADAPT** | `FOR UPDATE SKIP LOCKED`, bounded attempts, retained failure states. Delivery is Check-specific; Mesh needs connector-neutral idempotency, dead-letter policy, receipt linkage. |
| Hosted OIDC/JWKS auth + role mapping | `hosted_api.py:143-184, 216-250`, `integrations.py:36-53` | **ADAPT** | Supplies no SCIM/SAML enrollment, session policy, or workload identity. |
| SCM claim normalization | `integrations.py:73-125` | **ADAPT** | Provider verification stays upstream. **Raw webhook claims must never become authorization.** |
| Mission graph + budget-aware routing | `mission_graph.py:848-882` | **ADAPT** | A route recommendation is explicitly not spend or call authority. |
| LangGraph adapter | `mission_graph.py:805-820, 885-920` | **ADAPT** | See §5 — the pattern here is the architectural rule for all Mesh integrations. |
| BYOK provider router | `provider_router.py:184-195, 216-245, 321-368` | **ADAPT** | Returns no key values, makes no provider call, grants no spend authority. |
| Merkle selective disclosure | `privacy.py:31-84` | **ADAPT** | Ordered commitments and inclusion proofs — the tree construction anchoring needs. BBS/zkVM explicitly report unavailable (`privacy.py:87-121`). **Not** crypto-shredding. |

### Confirmed NEW — this is the actual remaining work
- **Memory record authority** — tenant/purpose-bound schema, encrypted payload + key references, versioning, retention class, read/write authorization.
- **Purpose binding** — `Principal` carries only subject, tenant, roles; `authorize()` checks action and tenant (`control_plane.py:35-90`). No purpose, purpose version, consent, or retention class is enforced.
- **Crypto-shredding / erasure** — no encrypted record store, key hierarchy, destroy operation, tombstone, or recoverability test. The evidence store writes canonical payload JSON directly (`control_plane.py:110-121`).
- **External anchoring** — `export_attestations()` writes unsigned local JSON only. No transparency-log submission, timestamp authority, or inclusion proof.

---

## 5. The receipts-authoritative rule (architectural constraint)

**Every framework, adapter, connector, or agent runtime is a caller of the receipt-governed API. None is an alternate proof authority.**

This pattern is already proven in code-factory: the LangGraph adapter delegates every node to `apply_mission_event()` (`mission_graph.py:885-920`), and `langgraph_doctor()` states explicitly that Code Factory receipts remain authoritative (`mission_graph.py:805-820`). A checkpoint cannot authorize or prove a mutation.

Mesh inherits this without exception:
- MCP tool calls, LangGraph nodes, connector callbacks, and SDK helpers all route through the same authorization and evidence path.
- No integration may write memory, sign, erase, or approve except by calling the governed API.
- No integration's own state (checkpoint, cache, session) may be presented as evidence.
- An agent may request verification; it may never self-authorize.

A bypass here voids the entire product thesis. If a framework integration cannot be expressed as an adapter over the governed API, do not ship the integration.

---

## 6. Operation-sensitive durability

**Do not rebuild audit as blanket fail-closed** — that is a denial-of-service vector.

| Class | Rule | On sink failure |
|---|---|---|
| Consequential | Mutation and audit event **commit atomically, or neither commits** | Operation **fails**, explicit error. Never proceeds unrecorded. |
| Sensitive read | Durable access receipt accepted **before** release | Read **denied**, explicit error. |
| Ordinary read | Receipt best-effort, async | Proceeds; marked `best-effort`, excluded from compliance export. |
| Telemetry | Best-effort | Dropped silently. **Never** compliance evidence. |

**Backpressure.** Outbox depth over threshold → reject consequential ops with `EVIDENCE_UNAVAILABLE` (retryable, `Retry-After`), continue ordinary reads, shed telemetry. **Never buffer consequential evidence in volatile memory** — that is fail-open in disguise.

**Reuse note.** The transaction and delivery patterns exist (`hosted_storage.py:243-387`). The generalization risk is real: that schema was designed for GitHub Check delivery, and inherited assumptions correct for Checks may be wrong for memory mutations. **Budget for this unit becoming closer to NEW than ADAPT if generalization proves harder than extension.**

---

## 7. Receipt specification

```
receipt {
  schema_version, receipt_id (uuid-v7), sequence (uint64, monotonic per tenant+chain),
  prev_hash, payload_hash, tenant_id,
  principal { id, type, home_tenant }, acting_as [principal] (depth <= 3),
  authority { grant_id, granted_by, expires_at }, purpose, purpose_version,
  operation { class, verb, resource_ref, store_adapter, store_version },
  decision (allow|verify|deny),
  policy { policy_id, policy_version, evaluated_rules[] },
  evidence_class (compliance|operational|telemetry),
  lineage_refs [receipt_id], occurred_at (rfc3339-utc, server clock),
  idempotency_key, signature { key_id, algorithm, value }
}
```

Canonicalization primitives are **PORTABLE** (`enterprise_receipts.py:52-61`). Confirm they cover this payload shape; version-pin the contract.

**A cross-language canonicalization conformance test is required**: an independently written verifier in a different language must reproduce identical bytes and validate the signature. Third parties will write verifiers.

**Verification must work offline** for a holder of receipt + public key + anchor. If it requires calling Mesh, it is not evidence — it is a database lookup.

---

## 8. Erasure vs immutability — **NEW**

Deletion obligations and hash chains conflict. Design for it.

1. Payloads containing personal data are encrypted with a per-subject data key.
2. Chain-relevant fields (hashes, sequence, principal IDs, timestamps, policy refs) stay unencrypted — metadata, not content.
3. On erasure, destroy the key. Payload permanently unrecoverable; chain intact.
4. Emit a **tombstone receipt** — itself consequential, with its own evidence.
5. Verifying a shredded receipt reports payload `erased`, never `corrupt`.
6. **Purge caches and indexes**, not only the record store.

**Do not implement erasure as row deletion or chain rewriting.** Note the current evidence store writes canonical payload JSON directly (`control_plane.py:110-121`) — encryption is an addition, not a configuration.

**Counsel-required:** whether crypto-shredding satisfies erasure obligations varies by jurisdiction and has been read differently by different authorities. Flag in `CLAIMS.md`; assert compliance nowhere.

---

## 9. Key management — **PORTABLE, extend lifecycle**

Port the existing model (`enterprise_receipts.py`). Keys in KMS/HSM, never in the app database or production env vars. Each key: `key_id`, activation, retirement, status (`active`/`retired`/`compromised`). **Rotation:** new key activates, old retires, public half published indefinitely — retirement is never deletion. **Compromise:** receipts in the suspected window verify as `disputed`, not silently trusted or discarded. Rotation must be **exercised**, not merely supported.

---

## 10. External anchoring — **NEW (Merkle primitives available)**

Anchoring makes T3 detectable. `export_attestations()` produces unsigned local JSON only.

Merkle commitment and inclusion-proof primitives already exist (`privacy.py:31-84`) — the tree construction is available, so the remaining work is the signed envelope, provider integration, and inclusion verification.

- Compute a per-tenant commitment over the interval's receipts.
- Publish where Mesh cannot retroactively alter it: append-only transparency log, third-party timestamping authority (RFC 3161 is the long-standing standard — **verify current tooling**), public blockchain, or at minimum a signed daily digest to customer-controlled storage.
- **Anchor interval is a product decision with a cost curve.** Specify (default hourly), make per-tenant configurable, document the detection window it implies.
- Anchor failure is alerting-critical and emits its own operational receipt. Define outage and replay behaviour.
- Customers retrieve their anchors and verify independently.

---

## 11. Ordering, idempotency, clocks

**Sequence** monotonic per `(tenant, chain)` — requires a single serialization point; do not assume timestamp ordering. **Idempotency:** client-supplied key; replay within the window returns the original receipt and re-executes nothing (minimum 24h retention). **Clocks:** `occurred_at` always server-assigned; client times recorded as `client_asserted_at`, never used for ordering, expiry, or policy. **Nonce window** enforced for replay rejection.

---

## 12. Implementation units and exit evidence

**Per-unit exit evidence replaces calendar estimates.** A unit is complete when its exit evidence exists in CI, not when the code compiles.

| Unit | Status | Work | Exit evidence |
|---|---|---|---|
| Memory record authority | **NEW** | Tenant/purpose-bound schema, encrypted payload + key refs, versioning, retention class, read/write authorization | Independent schema/authorization tests; receipt-linked CRUD traces |
| Crypto-shredding + erasure | **NEW** | Key hierarchy, destroy workflow, tombstone, cache/index purge, unrecoverability challenge | Deliberate-break erasure gate: payload unrecoverable **and** audit chain still verifiable |
| Purpose binding | **NEW** | Purpose declaration + version, purpose→action policy, consent/legitimate-use record, purpose in every authorization and evidence digest | Cross-purpose denial, replay, downgrade, and purpose-change mutation tests |
| External anchoring | **NEW** | Signed anchor envelope, provider integration, inclusion proof, retry/outage policy, offline verification bundle | Tamper and stale-anchor tests; third-party verifier with **no service call** |
| Hot-path mutation outbox | **ADAPT** | Generalize the hosted decision/outbox transaction to memory mutations and connector jobs without weakening RLS or idempotency | Concurrent writer, duplicate request, sink failure, tenant-crossing tests **plus measured hot-path latency** |
| Hosted auth + identity lifecycle | **ADAPT** | Retain OIDC/JWKS; add tenant enrollment, workload/service identity, session policy, directory lifecycle | Forged, stale, wrong-tenant, missing-purpose, key-rotation rejection receipts |
| Agent/MCP runtime surface | **ADAPT** | Wrap MCP/LangGraph calls around the native validator per §5; expose read/prepare/replay before privileged mutation | Tool-contract suite proving agents can request verification but **cannot self-authorize, sign, erase, or override** |
| Canonicalization conformance | **PORTABLE** | Version-pin; cross-language verifier | Independent different-language verifier reproduces bytes and validates signatures |

**Do not quote a calendar date.** Report units complete, units remaining, and blocking dependencies.

### Downstream milestones (gated on the units above)

**Memory CI — the customer wedge, ships first.** Tests a team's own configuration for cross-tenant leakage, unauthorized recall, missing provenance, stale recall, revocation/deletion cascade failures, purpose mismatch, unsafe derived memory, memory→action lineage, store-version compatibility. **Port `verify-validators` mutation testing** (`assurance.py:348-390`) so a check no validator proves reports `hollow_validator`. *Exit:* an external team installs it, runs it against their own store, gets reproducible receipts with zero WizeMe-specific assumptions.

**Gateway slice.** WizeMe's store, **one** external store, **one** canonical adapter contract: `authorize(...) → {decision, receipt, reasons[]}`, `execute(decision_receipt, operation) → {result, receipt}`, `describe() → {adapter_version, store_version, capabilities[], limitations[]}`. Certification fixtures run in CI against the live vendor so API drift fails as a compatibility test. `describe()` declares what it cannot support; the gateway **denies rather than silently degrades**. *Exit:* an operation returns a signed receipt verifying independently and naming the exact policy, principal, and store version. Only then add a second store.

**Full grants model.** Organizations, workspaces, principals, memberships, roles, subjects/authors/owners/custodians, resource grants, delegation and impersonation boundaries, purpose- and time-bound access, approvals, derived-memory inheritance, revocation cascades, separation of duty (`E_SELF_APPROVAL` semantics are PORTABLE). *Exit:* revoking a grant makes every dependent derived memory inaccessible with a receipt trail proving the cascade.

**Regulated packs.** Healthcare, finance, legal, insurance as configurations over a proven control plane — never forks. Backed by production receipts and counsel-reviewed claims. Not before the gateway has production evidence.

---

## 13. Agent-facing surface

Exposed via **MCP** and a **signed HTTP API**. Five tools — deliberately not store/retrieve:

| Tool | Contract |
|---|---|
| `authorize` | principal, tenant, resource_ref, action, purpose, provenance, policy_version → `{decision, receipt, reasons[]}` |
| `record` | decision_receipt, operation, idempotency_key → `{receipt_id, sequence, chain_position}` — atomic per §6 |
| `prove` | memory_ref or action_ref → portable signed lineage |
| `verify` | receipt (+ anchor) → `{valid, key_status, anchor_status, payload_state}` — **works offline** |
| `test` | configuration, suite → Memory CI results with reproducible receipts |

Every response asserting a decision carries a receipt — a decision without one is a bug, not a degraded mode. Never return `recorded`/`authorized`/`proven` before the durable evidence commits. **Deny is first-class and fully evidenced** — auditors care more about denials. §5 applies without exception.

**Errors** — extend the existing `E_*` taxonomy: `E_TENANT_BOUNDARY` · `E_ACTION_DENIED` · `E_SELF_APPROVAL` · `EVIDENCE_UNAVAILABLE` (retryable) · `POLICY_DENY` (terminal, with reasons) · `AUTHORITY_MISSING` · `PURPOSE_MISMATCH` · `ADAPTER_CAPABILITY_UNSUPPORTED` · `IDEMPOTENCY_CONFLICT` · `CHAIN_INTEGRITY_VIOLATION` (alerting-critical).

---

## 14. Performance and SLOs

**The hot-path latency envelope is entirely untested.** The existing outbox serves GitHub Check publication, which is batch-tolerant. Memory authorization is per-operation and latency-critical. The pattern transfers; the performance envelope has never been measured. Treat this as the highest-uncertainty item in the plan.

| Metric | Requirement |
|---|---|
| `authorize` p50/p95/p99 | Explicit budgets; policy evaluation must not require a network call to the store |
| `record` p95 (consequential) | Explicit budget including atomic commit — the honest cost of the guarantee |
| **Cold-start p95** | Explicitly budgeted; regression is a release blocker (known existing weakness) |
| Cross-runtime hop (if Python kernel behind TS gateway) | Budgeted and reported separately |
| Outbox depth | Alerting threshold; drives backpressure |
| Anchor lag | < 2× anchor interval; defines the tamper-detection window |
| Offline verification | Must not require network |

Publish customer-facing SLOs only from sustained-load measurement. **Apply `factory meter` discipline:** no percentage against zero data, projections labeled as models, baselines stated inline.

---

## 15. Observability

Operational telemetry is **never** compliance evidence and must be *structurally incapable* of appearing in `prove`/`verify` — enforce by type, not convention. Alert on chain integrity violations, anchor failure/lag, tenant isolation violations, outbox depth, key-rotation failures, adapter certification failures. Each also emits an operational-class receipt. **Never log receipt payloads to application logs.**

---

## 16. Migration

Dual-write and backfill; never a big-bang cutover. Every migrated record gets a synthetic principal and tenant derived from its existing owner, recorded as a migration event with its own evidence. **Reversible** until exit evidence passes on the migrated dataset. Isolation tests run against the **migrated** data, not fixtures. Pre-migration records stay verifiable — document the discontinuity honestly. **Fabricating retroactive receipts would be the single worst thing this project could do.**

---

## 17. Product boundaries

The WizeMe consumer app is the **reference implementation** — proof the primitives work under real multi-lane load — not a second product. Do not expand its surface.

**code-factory stays a separate product.** Shared primitives, separate products, separate buyers. Merging them is the diffusion problem in a new costume.

---

## 18. Threat model

| # | Adversary | Required property |
|---|---|---|
| T1 | Compromised agent | Every action bound to principal + authority + purpose; anomalies visible in lineage |
| T2 | Malicious tenant | Cross-tenant access impossible by construction (RLS); tested against migrated data |
| T3 | Insider with DB write access | Tampering detectable via chain + signature + **external anchor**; detection must not depend on the DB being honest |
| T4 | Replay attacker | Idempotency + monotonic sequence + nonce window |
| T5 | Availability attacker | Degradation per §6; consequential ops fail rather than proceed unrecorded; no global halt |
| T6 | Repudiating operator | Signed, anchored, externally verifiable receipts |
| T7 | Key compromise | Bounded blast radius; prior receipts verify; compromise window identifiable |
| T8 | Framework bypass | No integration writes, signs, erases, or approves except through the governed API (§5) |

**Explicit non-goal:** Mesh does not prevent a memory store from lying about its own contents. It proves what the gateway observed and decided. State this boundary in customer documentation.

---

## 19. Prohibited actions

1. Advance a claim label without its exit evidence, or drop the domain qualifier.
2. Rebuild anything tagged PORTABLE in §4.
3. Build storage, retrieval, ranking, or embedding as a core feature.
4. Rebuild audit as blanket fail-closed.
5. Buffer consequential evidence in volatile memory as a "temporary" measure.
6. Implement erasure as row deletion or chain rewriting.
7. Sign non-canonicalized serialization, or skip the cross-language conformance test.
8. Make verification depend on calling Mesh's API.
9. Store signing keys in the application database or production env vars.
10. **Let any framework, adapter, or checkpoint act as an alternate proof authority (§5).**
11. **Treat raw webhook or SCM claims as authorization** (`integrations.py:73-125`).
12. Support a second external vendor before the first adapter contract survives integration.
13. Surface telemetry-class data through `prove` or `verify`.
14. Describe any capability as "auditor-grade" before its exit evidence exists.
15. Assert legal or regulatory compliance in code, comments, or docs — flag counsel-required.
16. Fabricate retroactive receipts for pre-migration data.
17. Publish a performance or savings figure violating `factory meter` discipline.
18. Quote a calendar estimate; report units and blockers instead.

---

## 20. Execution order

1. **Commit this PRD into the repository.**
2. Confirm §4 against the current code-factory checkout; report drift from commit `4b8b19c0`.
3. `CLAIMS.md` reproducing §1 verbatim, plus the runtime decision (Python kernel as a service behind the gateway, or port to TypeScript) with rationale.
4. Verification pass against §3 — confirm or correct the WizeMe inventory; **report discrepancies rather than trusting this document.**
5. Threat-model review (§18) against the real codebase; report which threats current architecture cannot address.
6. Implement units in §12, NEW first — memory record authority and purpose binding gate everything downstream.
7. **Measure the hot-path latency envelope early** (§14). It is the highest-uncertainty item and could reshape the design.
8. Migration plan (§16) with reversibility demonstrated.
9. Only then Memory CI.

**Run steps 1–5 as a discrete invocation and report back.**

---

## 21. Honest constraints

- The sellable product today is **Memory CI**, and it is not sellable until its exit evidence exists.
- The proof substrate is **not speculative** — canonical bytes, DSSE signing, offline verification, revocation, PostgreSQL RLS, an atomic outbox, OIDC authentication, mission graphs, Merkle disclosure, and MCP starter generation are implemented and pass 285 tests at the reviewed commit. That materially shortens the work and is the strongest available answer to solo-founder execution risk. **Put the repository in the data room** — under technical diligence, not the IP schedule; the permissive license means it conveys capability, not exclusivity.
- **What remains is still hard.** Memory record authority, purpose binding, crypto-shredding, and anchoring are genuinely new. The outbox generalization may prove closer to new than adapted. And the hot-path latency envelope has never been measured.
- Treat any generated first draft of the NEW units as **something to attack, not something to ship.** The failure modes in §7, §8 and §9 are silent and pass happy-path tests.
- Enterprise buyers will run a security questionnaire and likely require SOC 2. Not substituted for here, and not budgeted.
- **No amount of this closes the demand-side gap.** Every unit above proves the thing works and was built well. None proves anyone wants it. That evidence has to be gathered in conversation with teams deploying agents against regulated data, and it is the weakest link in the story.

The defensible asset is not the mesh and not the memory. **It is portable, enforceable proof of how information moved through the mesh and influenced an action.**
