# Code Factory reuse map — source-verified

**Status:** source review complete for Task 4  
**Reviewed checkout:** `4b8b19c098dc61c8451f9ef701861fc807ff7a03` (`Fix JetBrains Marketplace publish runner (#21)`)  
**Evidence convention:** `[R]` repo-verified, `[D]` data-verified, `[F]` founder-supplied or missing, `[U]` unknown. Absence is recorded as a finding.

## Scope and boundary

[R] This review read the implementation rather than treating README or product-plan language as proof. The original Mesh PRD §4 table is not present in this checkout, so a literal row-by-row redline against its prior labels is `[U]`. The corrected map below is therefore the source-backed replacement baseline; the missing PRD artifact should be attached before a formal estimate is approved.

[R] The current repository has a clean full-suite result at the reviewed commit:

```text
python -m pytest -q
285 passed, 2 skipped in 36.41s
```

[R] This is evidence that the current Code Factory checkout passes its own tests. `[U]` It is not evidence that a Mesh runtime, memory store, hosted service, or external anchor exists.

## Corrected reuse table

| Code Factory surface | Source evidence | Corrected tag | Portability into Mesh | Boundary that must remain explicit |
| --- | --- | --- | --- | --- |
| Canonical JSON and SHA-256 digests | `[R]` `factoryline/enterprise_receipts.py:52-61`; `[R]` `factoryline/control_plane.py:63-73` | **PORTABLE** | Portable as code; both modules expose deterministic serialization/digest primitives. | The receipt schema and canonicalization contract must be version-pinned in Mesh; a digest proves bytes, not issuer identity. |
| Receipt v2 DSSE / Ed25519 signing | `[R]` `factoryline/enterprise_receipts.py:193-215` | **PORTABLE** | Portable as code when the reviewed `cryptography` dependency is available. | Key custody, identity issuance, and signer authorization are deployment responsibilities; the local private-key loader is not a managed KMS. |
| Offline receipt verification, policy binding, and revocation | `[R]` `factoryline/enterprise_receipts.py:224-255`; `[R]` `factoryline/enterprise_receipts.py:275-311` | **PORTABLE** | The verifier can run offline with a receipt, trust root, optional policy bundle, and revocation bundle. | Verification does not provide transparency-log inclusion, trusted timestamping, or key lifecycle management. Those remain net-new. |
| Local tenant-scoped evidence, roles, approvals, and audit chain | `[R]` `factoryline/control_plane.py:35-90`; `[R]` `factoryline/control_plane.py:92-151`; `[R]` `factoryline/control_plane.py:208-225`; `[R]` `factoryline/control_plane.py:304-370` | **ADAPT** | The authorization and hash-linked audit patterns are reusable; the SQLite schema is a local reference implementation. | `Principal` has subject, tenant, and roles but no purpose; the local store is not a hosted multi-tenant memory database, and authorization still depends on a trusted identity adapter. |
| Hosted PostgreSQL tenant isolation and assurance outbox | `[R]` `factoryline/hosted_storage.py:33-100`; `[R]` `factoryline/hosted_storage.py:130-153` | **ADAPT** | Real PostgreSQL persistence, forced RLS, tenant routing, and a transactional outbox already exist for hosted PR assurance. | This is not a generic memory store. The schema is PR-delivery/approval-specific and must be generalized before it can serve memory mutations. |
| Atomic decision plus publication outbox | `[R]` `factoryline/hosted_storage.py:243-322` | **ADAPT** | The approval decision, OIDC-use record, and unique GitHub Check outbox row commit in one transaction. | The hot-path guarantee has not been demonstrated for memory writes, key destruction, or Mesh connectors. The PRD item should move from NEW to ADAPT only for this bounded hosted assurance path. |
| Concurrent outbox delivery and retry state | `[R]` `factoryline/hosted_storage.py:324-387` | **ADAPT** | `FOR UPDATE SKIP LOCKED`, bounded attempts, publish, and retained failure states are reusable delivery patterns. | Delivery is currently GitHub Check-specific; Mesh needs connector-neutral idempotency, dead-letter policy, and receipt linkage. |
| Hosted OIDC/JWKS authentication and role mapping | `[R]` `factoryline/hosted_api.py:143-184`; `[R]` `factoryline/hosted_api.py:216-250`; `[R]` `factoryline/integrations.py:36-53` | **ADAPT** | Verified OIDC claims become a tenant-bound `Principal`; hosted readiness requires PostgreSQL and usable JWKS. | This does not supply SCIM/SAML enrollment, managed session policy, workload identity, or a Mesh-wide auth service. |
| SCM claim normalization | `[R]` `factoryline/integrations.py:73-125` | **ADAPT** | GitHub, GitLab, and Azure DevOps event normalization and signature-verification boundary are reusable. | Provider verification remains upstream of normalization; raw webhook claims must never become authorization. |
| Trace verification and in-toto/SLSA-shaped export | `[R]` `factoryline/proof.py:398-461` | **PORTABLE** | Trace-to-statement generation is reusable as an export adapter. | The function explicitly exports **unsigned** statements. It is not an external anchor, transparency-log entry, or issuer-authenticated attestation. |
| Policy mutation gate | `[R]` `factoryline/assurance.py:329-345`; `[R]` `factoryline/assurance.py:348-390` | **PORTABLE** | The mutation model and argv-only challenge runner are portable to Mesh validators. | A Mesh policy still needs purpose binding, memory authorization rules, and an independent verifier; the existing gate does not add those semantics. |
| Durable mission graph and budget-aware routing | `[R]` `factoryline/mission_graph.py:1-5`; `[R]` `factoryline/mission_graph.py:848-882` | **ADAPT** | The state machine, idempotent events, bounded budgets, route explanation, and human-interrupt concepts are useful orchestration primitives. | A route recommendation is explicitly not provider-call or spend authority; Mesh must retain a separate execution/approval boundary. |
| LangGraph adapter | `[R]` `factoryline/mission_graph.py:805-820`; `[R]` `factoryline/mission_graph.py:885-920`; `[R]` `docs/LANGGRAPH_OPS.md:3-39` | **ADAPT** | The optional adapter compiles a LangGraph around the native transition guard and can use a SQLite checkpointer. | LangGraph checkpoints are secondary. MCP or any agent framework must call the Code Factory transition validator and receipts; a checkpoint alone cannot authorize or prove a mutation. |
| Secret-free BYOK provider router | `[R]` `factoryline/provider_router.py:184-195`; `[R]` `factoryline/provider_router.py:216-245`; `[R]` `factoryline/provider_router.py:321-368` | **ADAPT** | Policy normalization, IDE/provider/model rails, credential-presence checks, cache continuity, and route explanations are reusable. | The router returns no key values, makes no provider call, and grants no spend authority. Mesh needs a runtime credential broker and per-purpose/provider policy. |
| MCP target starter generator | `[R]` `factoryline/target_compiler.py:531-620`; `[R]` `factoryline/cli.py:747-785` | **PORTABLE** | The target compiler can generate a local stdio MCP starter with an explicit tool contract and deterministic tests. | The generated `echo` server is a starter, not a production Mesh control surface. A governed MCP server must expose only receipt-backed operations and preserve human approval boundaries. |
| Merkle selective disclosure | `[R]` `factoryline/privacy.py:31-84` | **ADAPT** | Ordered Merkle commitments and inclusion disclosures are portable privacy-plane primitives. | BBS issuance and zkVM proof integrations explicitly refuse or report unavailable backends at `[R]` `factoryline/privacy.py:87-121`; this is not crypto-shredding or erasure. |

## Specific corrections to the reuse hypothesis

1. **`psycopg` is not vestigial.** `[R]` It is an optional hosted dependency in `pyproject.toml:55-58`, and `PostgresAssuranceStore` is implemented in `factoryline/hosted_storage.py:130-387`. The atomic outbox item is therefore **ADAPT**, not NEW, for hosted GitHub PR assurance. `[U]` No source evidence shows that the same transaction/outbox contract already covers Mesh memory operations; that part remains new work.

2. **LangGraph integration is real but deliberately non-authoritative.** `[R]` `langgraph_doctor()` reports the optional adapter and states that Code Factory receipts remain authoritative (`factoryline/mission_graph.py:805-820`). `[R]` The adapter delegates each node to `apply_mission_event()` (`factoryline/mission_graph.py:885-920`). The Mesh MCP design should reuse this pattern: framework calls are adapters around the receipt-governed transition API, never alternate proof authorities.

3. **External anchoring remains NEW.** `[R]` `export_attestations()` calls its output “unsigned” and writes only local JSON files (`factoryline/proof.py:398-461`). There is no source-level transparency-log submission, timestamp authority, or independently verifiable inclusion proof in this checkout. `[U]` A production anchor provider, retention policy, and outage/replay behavior still need to be selected.

4. **Crypto-shredding and memory erasure remain NEW.** `[R]` The privacy module provides Merkle disclosure, BBS status guards, and a zkVM pilot status, but no encrypted memory-record store, key hierarchy, destroy operation, tombstone, or recoverability test (`factoryline/privacy.py:31-121`). The existing evidence store stores canonical payload JSON directly (`factoryline/control_plane.py:110-121`).

5. **Purpose binding remains NEW.** `[R]` `Principal` carries only `subject`, `tenant_id`, and `roles`, and `authorize()` checks action and tenant (`factoryline/control_plane.py:35-90`). No purpose, purpose version, consent, retention class, or purpose-to-action policy is enforced by the control-plane schema.

6. **Authentication is adapter-dependent, not universal.** `[R]` Hosted approval decisions verify OIDC/JWKS before building a principal (`factoryline/hosted_api.py:216-250`). `[R]` The local control API documentation says `X-Factory-*` headers are an adapter boundary, not authentication (`docs/CONTROL_PLANE.md:45-56`). Mesh must not describe the local header path as production auth.

## Mesh-relevant surfaces the prior table should include

- **Mission graph operations:** status, history, verification, Mermaid export, idempotent guarded events, budgets, routing explanations, human interrupt, and context refresh are exposed as a coherent runtime surface (`factoryline/cli.py:747-771`; `[R]` `factoryline/mission_graph.py:848-920`).
- **Provider/IDE policy rails:** the provider CLI and JetBrains-specific route selection already distinguish policy verification from provider execution (`factoryline/cli.py:773-785`; `[R]` `factoryline/provider_router.py:321-368`).
- **Capability-pack and target compilation:** the MCP, API, worker, web, mobile, and agent-UI starters are generated from explicit packs; the MCP pack is intentionally stdio-only and credential-free (`factoryline/target_compiler.py:531-620`; `[R]` `factoryline/builtin_packs/target-mcp/pack.yaml:1`).
- **Hosted PR assurance:** installation-to-tenant binding, dynamic secret references, OIDC, PostgreSQL RLS, and the Check outbox form a reusable reference for connector durability (`factoryline/hosted_api.py:186-228`; `[R]` `factoryline/hosted_storage.py:164-240`).
- **Privacy disclosure primitives:** Merkle inclusion proofs can support minimum-claim disclosure, but they do not replace encrypted storage or erasure (`factoryline/privacy.py:31-84`).

## Portability and remaining Milestone 1 work

[R] The evidence supports a shorter and more precise plan than “rebuild the control plane.” `[R]` Most of the proof mechanics already exist, but they are not yet a memory-authority product. The remaining work is best expressed as implementation units, not an invented calendar estimate:

| Remaining unit | Status | What must be added or adapted | Exit evidence required |
| --- | --- | --- | --- |
| Memory record authority | **NEW** | Tenant/purpose-bound record schema, encrypted payload/key references, versioning, retention class, and read/write authorization. | Independent schema/authorization tests and receipt-linked CRUD traces. |
| Crypto-shredding and erasure | **NEW** | Per-tenant or per-record key hierarchy, destruction workflow, tombstone, cache/index purge, and unrecoverability challenge. | A deliberate-break erasure gate proving payload is unrecoverable while the audit chain remains verifiable. |
| Purpose binding | **NEW** | Purpose declaration/version, purpose-to-action policy, consent/legitimate-use record, and purpose in every authorization/evidence digest. | Cross-purpose denial, replay, downgrade, and purpose-change mutation tests. |
| External anchoring | **NEW** | Signed anchor envelope, transparency/timestamp provider, inclusion proof, retry/outage policy, and offline verification bundle. | Tamper and stale-anchor tests plus a third-party verifier with no service call. |
| Hot-path mutation outbox | **ADAPT** | Generalize the hosted PostgreSQL decision/outbox transaction to memory mutations and connector jobs without weakening RLS or idempotency. | Concurrent writer, duplicate request, sink failure, and tenant-crossing tests. |
| Hosted authentication and identity lifecycle | **ADAPT** | Retain OIDC/JWKS verification; add tenant enrollment, workload/service identity, session policy, and enterprise directory lifecycle as required by the chosen deployment. | Forged, stale, wrong-tenant, missing-purpose, and key-rotation rejection receipts. |
| Agent/MCP runtime surface | **ADAPT** | Wrap LangGraph/MCP calls around the native validator and expose read/prepare/replay operations before privileged mutation operations. | A tool-contract suite proving agents can request verification but cannot self-authorize, sign, erase, or override. |

### Revised readiness conclusion

[R] Code Factory is a strong **proof and policy substrate**: canonical bytes, DSSE verification, tenant-scoped local authorization, hosted PostgreSQL/RLS, an atomic GitHub Check outbox, mission graphs, LangGraph adaptation, provider rails, MCP starter generation, and Merkle disclosure are implemented. `[U]` It is not yet evidence that Mesh has a production memory authority, external anchor, purpose-bound authorization, crypto-shredding, or connector-neutral hot-path durability. The defensible Milestone 1 posture is therefore **reuse the receipt/control primitives, adapt the hosted and framework boundaries, and implement the memory/privacy/anchor semantics as new work**.

## Adjacent packaging finding

[R] The repository already declares the canonical repository and homepage links in `pyproject.toml:40-45`, and the publication metadata test covers them. `[R]` The hosted Postgres and LangGraph dependencies are explicitly declared in `pyproject.toml:55-62`. A legacy `Home-page` field observed by third-party tooling is not represented in PEP 621 `[project.urls]`; changing packaging metadata should be handled as a separate release task and should be verified from the built wheel before publication.
