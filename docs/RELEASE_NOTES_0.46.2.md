# Code Factory 0.46.2 — Proof That Stays With the Work

## The story

**Mission.** You asked an AI coding agent to change a real system. You need to move quickly without accepting a green test, a polished diff, or an agent summary as proof.

**Tension.** The agent can misunderstand intent, quietly weaken its own test gate, reuse an old receipt, or hand off work without making the risk visible to the next reviewer.

**Guidance.** Code Factory 0.46.2 adds a connected review path: clarify intent, prove the behavior, independently challenge it, trace the evidence, and hand off only what a human can inspect.

**Agency.** You choose the scope, the policy pack, the autonomy level, and the next action. Agents may propose; they cannot silently widen scope, weaken a blocking rule, or release work.

**Transformation.** The review result becomes a short, evidence-linked briefing rather than a wall of tool output. IDE, MCP, and A2A agents receive the same supervised playbook.

**Continuity.** When a receipt is stale, a diff drifts, a capture is weak, or a gate is missing, FactoryLine blocks with the smallest deterministic repair. It does not pretend an unknown is a pass.

## What changed

- **Deep Defect Mesh:** Signed analyzer/rule contracts, strict SARIF intake, required canaries, trace and suppression checks, prioritized repair guidance, and content-addressed receipts.
- **Connected deep review:** CLI evaluation, read-only MCP/Mission Control status, bounded Graph Ops lineage, and repair comparisons that stop on policy changes, regression or stagnation. Receipt self-hashes are not signer authentication or release approval.

- **IDE and A2A Agent Playbook:** Plain-language operating cards for intent, proof, challenge, trace, and handoff. External agents require scoped, expiring identity and capability envelopes; supervised is the default.
- **Mission Control briefing contract:** Every action explains what will happen, why, inputs, uncertainty, authority, evidence, and one next safe action. Advanced modules remain contextual; blockers stay visible.
- **Earned Proof Moments:** After a user-visible verified outcome, the UI can show a redacted receipt and offer a one-time optional invitation for an honest review. It never requests stars, positive feedback, or trades rewards for reviews.
- **Intent-to-Diff Review:** Blocks scope drift and declared forbidden behavior in a supplied diff manifest even when a test is green.
- **Evidence Freshness and Replay Defense:** Rejects receipts bound to another commit or environment, expired evidence, duplicate receipt IDs, and missing nonces.
- **Team Policy Packs:** Keeps policy ownership human/trusted-source controlled, versioned, and mapped to explicit gates. Agent-owned policy cannot become the baseline.
- **SpecLine to ForgeLine promotion:** Execution promotion is sealed to the approved intent digest and only the capability gates selected for that work. AppForge stays optional and activates only for explicit mobile delivery.
- **AppForge delivery integrity:** For explicit iOS/App Store work, requirements and capture evidence must be candidate-bound, explicit, native-build classified, and hash-reconciled. This is a capability pack, not the default Code Factory path.
- **Six-lane runtime assurance:** One signed plan now coordinates stateful invariants, tenant isolation, concurrency/recovery, consumer contracts, migration integrity, and performance/resource retention. Known-bad controls must fail, agent-proposed thresholds stay advisory, and every visible result includes a consequence and next repair.
- **Actionable Mission Control:** FactoryLine, CLI, and MCP show the same six lane states and evidence digests. Missing engines, missing observations, stale contracts, profiler gaps, and tampered receipts remain incomplete or blocked rather than becoming green.

## Truth boundary

These controls validate supplied local contracts, metadata, paths, hashes, and declared gates. They do not independently understand code semantics, operate an IDE/agent/device, guarantee a defect was found, execute a provider action, or grant release approval.
