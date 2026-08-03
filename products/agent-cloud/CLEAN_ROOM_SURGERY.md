# Memory and Trust clean-room surgery protocol

## Decision

If the Week 2 rights/provenance gate does not approve a WizeMe fork, Code Factory shall build `factory-memory-core` and `factory-trust-core` as clean-room implementations. A clean-room implementation is new work derived from independently authored behavioral contracts—not a fork, extraction, refactor, translation, or copy of WizeMe source.

The WizeMe application folder is outside the authorized workspace for this procedure. No agent, script, test, build, indexer, search command, or dependency resolver may read from or write to it.

## Non-negotiable invariants

1. WizeMe application source never enters the clean implementation context.
2. No source, comments, tests, schemas, prompts, migrations, assets, names, or generated artifacts are copied or mechanically translated.
3. Only approved inputs listed in the evidence manifest may inform implementation.
4. Memory cannot grant authority; Trust alone makes action-authorization decisions.
5. Memory and Trust use different stores, keys, service identities, release artifacts, and administrative credentials.
6. Every participant records role, approved inputs, outputs, and contamination attestations.
7. A contamination signal stops work and quarantines affected artifacts; schedule pressure cannot waive the stop.
8. Human legal/security approval is required before the first implementation commit and before release.

## Roles and context wall

| Role | May access WizeMe source? | Receives | Produces |
|---|---:|---|---|
| Rights officer | Only when legally authorized | ownership, licenses, repository history | written fork or clean-room decision |
| Reference/specification team | No by default; black-box behavior and approved public/user-authored material only | approved input manifest | behavioral requirements, examples, protocol transcripts |
| Clean implementation team | No | sealed contracts and test vectors | new source, tests, migrations, documentation |
| Independent validation team | No | sealed contracts, test vectors, built artifacts | conformance, security, mutation, and provenance receipts |
| Release authority | No source access required | evidence bundle and approvals | signed release/no-release decision |

One person may not act as both rights officer and sole release authority. Anyone previously exposed to restricted WizeMe implementation details must disclose that exposure; legal/security decides whether they may join the clean implementation team.

## Authorized inputs

The clean team may use only inputs recorded by SHA-256 in `clean-room/evidence-manifest.json`:

- this PRD and the independently authored service contracts;
- user-authored product requirements supplied for the clean-room project;
- public standards and dependency documentation with recorded URL/date/license;
- black-box request/response transcripts produced through an authorized interface;
- synthetic test vectors created from the contracts;
- Code Factory primitives already owned and licensed for reuse.

The clean team may not use decompiled output, source-derived tests, copied database schemas, screenshots of source, generated summaries of restricted source, or model context that contains restricted source.

## Surgical procedure

### Gate CR-0 — freeze and boundary declaration

1. Record the authorized Code Factory root and the prohibited WizeMe roots without enumerating their contents.
2. Configure search, indexing, backup, IDE, and agent tools to exclude prohibited roots.
3. Create empty independent repositories or packages for Memory and Trust.
4. Record participants and prior-exposure declarations.

**Pass:** boundary manifest exists, prohibited-root canary tests fail closed, and a human approves the context wall.

### Gate CR-1 — rights and origin decision

1. Rights officer records canonical upstream identity, ownership, licenses, notices, patents/trademarks, third-party dependencies, and permitted uses.
2. Select exactly one origin per service: `approved_fork` or `clean_room`.
3. For `clean_room`, prohibit source import and upstream merge workflows.

**Pass:** signed decision exists by end of Week 2. Missing evidence selects `clean_room`; it never implies permission to copy.

### Gate CR-2 — independently authored contracts

Define request/response schemas, error codes, state transitions, tenancy rules, cryptographic formats, deletion semantics, performance budgets, and observable postconditions without implementation detail.

Required Memory contract areas:

- write, retrieve, inspect, explain, correct, expire, delete, export, and legal hold;
- tenant, agent, subject, source, purpose, provenance, confidence, retention, and policy version;
- poisoning and cross-tenant rejection behavior.

Required Trust contract areas:

- evaluate, grant, approve, revoke, verify, and receipt operations;
- normalized action binding, audience/resource scoping, expiry, nonce/idempotency, budget reservation, and key rotation;
- expired, replayed, wrong-audience, wrong-resource, over-budget, and revoked rejection behavior.

**Pass:** contracts are hash-sealed, reviewed by security/product, and contain no code-shaped material from WizeMe.

### Gate CR-3 — adversarial test vectors before implementation

Create tests that initially fail because no implementation exists:

- cross-tenant read/write and identifier-substitution attempts;
- memory poisoning, indirect prompt injection, malformed provenance, deletion, and legal-hold conflicts;
- capability replay, expiry, audience/resource mismatch, concurrent budget races, approval substitution, revocation, and signature mutation;
- service separation tests proving Memory cannot authorize and Trust cannot read semantic memory content;
- export/import, migration, rollback, and compatibility fixtures.

**Pass:** validators fail when requirements are deleted or inverted; surviving mutants block implementation.

### Gate CR-4 — isolated implementation

1. Implement only against the sealed contracts and failing clean-room tests.
2. Use fresh package namespaces and original internal structure.
3. Record dependency origin/license and produce an SBOM on every build.
4. Reject convenience imports that cross the Memory/Trust boundary.
5. Keep all credentials external and runtime-injected.

**Pass:** tests pass in an environment with no WizeMe path mounted or available.

### Gate CR-5 — independent validation

The validation team performs contract conformance, mutation, fuzz/property, tenant-isolation, replay, cryptographic, migration, rollback, dependency, and reproducible-build checks. Black-box comparison is limited to documented behavior and may not expose the clean team to restricted implementation material.

**Pass:** zero surviving security/authority mutants, zero accepted cross-tenant cases, zero hard-budget overruns, and independently reproducible signed artifacts.

### Gate CR-6 — provenance and release

The evidence bundle contains:

- rights/origin decision and participant attestations;
- approved-input hashes and contract hashes;
- clean repository history from first commit;
- dependency SBOM, vulnerability results, and licenses/notices;
- test, mutation, isolation, migration, rollback, and reproducible-build receipts;
- legal, security, and release-authority approvals.

**Pass:** all evidence verifies and no contamination incident remains open. Otherwise release is denied.

## Contamination stop procedure

Stop immediately if restricted source, source-derived content, or an unapproved artifact appears in context or workspace.

1. Do not copy, summarize, commit, or continue using the material.
2. Record time, actor/tool, path, and artifact hash without recording restricted content.
3. Quarantine only the affected clean-room artifacts; do not alter the WizeMe application.
4. Notify legal/security and suspend affected contributors or agents.
5. Determine the last uncontaminated commit from evidence.
6. Rebuild affected work from sealed contracts with an eligible clean team.
7. Resume only after a signed clearance decision.

## Autonomy classification

This workflow is `human_controlled` until two independent service releases complete all gates without contamination or surviving validators. It may then become `supervised`. It cannot become `autonomous` without pre-, post-, and invariant validators plus a clean receipt history and explicit governance approval.

## What this protocol does not prove

The procedure does not itself establish legal non-infringement, patent clearance, regulatory compliance, or ownership. Qualified counsel and security reviewers make those decisions. It establishes a traceable engineering boundary and evidence record for their review.
