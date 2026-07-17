# Capability Packs v0.17 Specification

## User and outcome

The target user is a product engineer who needs to choose a software shape and
its language, surface, capability, data, and operator constraints before code
generation. They need one reviewable composition whose compatibility,
provenance, failure behavior, deployment guidance, and authority boundary are
explicit, so adding product diversity does not weaken release proof.

## Functional requirements

- **REQ-PACK-CATALOG:** The built-in inventory shall contain 29 signed packs
  across target, surface, language, capability, data, and operations kinds.
- **REQ-PACK-TARGETS:** Target inventory shall expose CLI, API, MCP, worker,
  web, mobile, and supervised agent UI generators.
- **REQ-PACK-CONTRACT:** Every pack shall contain a generator adapter,
  validators, goldens, canaries, all eight UX states, a deny-breaking-change
  migration policy, deployment profiles, and an explicit compatibility object.
- **REQ-PACK-MUTATION:** Pack validation shall reject all ten contract
  mutations before installation or composition.
- **REQ-PACK-COMPOSE:** Composition shall verify signatures and mutations,
  reject duplicate, conflicting, missing-kind, or target-incompatible packs,
  and write one atomic hash-bound receipt.
- **REQ-PACK-AUTHORITY:** Composition shall never grant generation, execution,
  deployment, or publication authority.
- **REQ-PACK-COMPAT:** Existing deployment profile IDs shall remain stable.

## Non-functional requirements

- **NFR-PACK-ATOMICITY:** Installation and composition writes must use staged
  atomic replacement and preserve existing data unless force is explicit.
- **NFR-PACK-PORTABILITY:** Text signatures must verify across CRLF and LF
  checkout normalization; binary files remain byte-exact.
- **NFR-PACK-PROVENANCE:** Release signing private keys must remain outside the
  repository; only public trust roots and signatures are shipped.

## Non-goals

- A composition does not generate product-specific auth, billing, search,
  offline sync, data pipelines, or admin workflows.
- A pack does not invoke a model, connector, network service, deployment, or
  external message.
- Pack verification is not release approval and cannot merge or publish code.
- This release does not add a hosted pack registry or download untrusted packs.

## Risks, failure behavior, and rollback

- **Signature or manifest drift:** fail with `PACK_VALIDATION_FAILED`; preserve
  the existing installed pack and composition.
- **Incompatible selection:** fail with `PACK_COMPOSITION_INCOMPATIBLE`; write
  no receipt and identify the exact pack and target or missing kind.
- **Generator unavailable:** fail with `PACK_GENERATOR_UNSUPPORTED` before the
  destination is promoted; remove staging and leave existing output unchanged.
- **Atomic swap failure:** restore the previous installation and emit
  `PACK_ROLLBACK_RESTORED`.
- **Release regression:** revert the v0.17 commit/tag, invalidate receipts bound
  to its source commit, and republish only after the full matrix and clean-wheel
  smoke pass again. Existing deployment profile IDs prevent route drift.

## Requirement traceability

| Requirement | Deterministic proof |
| --- | --- |
| REQ-PACK-CATALOG | catalog count/kind/signature test in `test_capability_packs.py` |
| REQ-PACK-TARGETS | target inventory plus all-target parameterized compile test |
| REQ-PACK-CONTRACT | `validate_pack` required-path, UX, migration, deployment, compatibility checks |
| REQ-PACK-MUTATION | ten mutation cases asserted for all 29 packs |
| REQ-PACK-COMPOSE | compatible and incompatible composition tests plus CLI test |
| REQ-PACK-AUTHORITY | exact four-field false authority assertion |
| REQ-PACK-COMPAT | external deployment profile regression test |
| NFR-PACK-ATOMICITY | existing install refusal and simulated swap rollback tests |
| NFR-PACK-PORTABILITY | CRLF/LF signature portability test |
| NFR-PACK-PROVENANCE | generator script requires external private key; repository secret scan |

## Acceptance scenarios

```gherkin
Scenario: Validate the complete built-in catalog
  Given the 29 first-party pack directories
  When each pack is validated with signature and mutation checks enabled
  Then every signature verifies
  And all 10 mutations per pack are rejected

Scenario: Compose a compatible web product vocabulary
  Given target-web, surface-nextjs, language-typescript, and capability-auth
  When factory pack compose writes the review-portal composition
  Then the receipt is hash-bound and atomic
  And generate, execute, deploy, and publish authority are false

Scenario: Reject an incompatible surface
  Given target-worker and surface-expo
  When factory pack compose evaluates the selection
  Then it fails with PACK_COMPOSITION_INCOMPATIBLE
  And no composition receipt is written

Scenario: Generate every executable target
  Given each of cli, api, mcp, worker, web, mobile, and agent-ui
  When factory create compiles the target from one prompt
  Then the target includes source, SSAT, smoke, coverage, architecture, and a compile receipt
  And the promotion state remains blocked
```
