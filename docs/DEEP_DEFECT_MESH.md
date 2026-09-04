# Deep Defect Mesh

An analyzer finds a risky path. A developer fixes it. How does the next reviewer
know whether the fix helped—or merely hid the warning?

Code Factory connects those observations to explicit policy and repair evidence.
It complements hollow-test checks and the six Runtime Assurance lanes; it is not
a replacement static analyzer, sandbox or autonomous repair service.

## Operator path

1. A policy owner signs the analyzer, rule, source and canary contract. Keep its
   trust-root hash independently pinned, not supplied by an untrusted agent.
2. Produce target and separate known-bad canary SARIF reports outside CF. Bind
   exact report/source hashes. Unsupported or missing evidence fails closed.
3. Run `factory deep-audit evaluate --plan <plan> --trust-root <trust>
   --trust-root-sha256 <sha256> --root <workspace>`.
4. Inspect `factory deep-audit status --root <workspace>`, MCP
   `factory.deep_audit_status`, or Mission Control. Repair items explain the
   obligation, location, consequence and next investigation.
5. After a separately authorized fix and new analyzer run, use
   `factory deep-audit compare --root <workspace> --before <receipt>
   --after <receipt>`. Paths are workspace-relative. Stop for policy changes,
   regression or stagnation. Only a human may approve the result.

Graph Ops shows at most 50 finding chains and links the complete receipt.
Corroboration and compound-risk clusters are investigation signals, not causal
proof. Missing evidence is NOT_RUN or INCOMPLETE, never a green assessment.

## What is verified

Signed intake checks the declared contract and bound files. Local status and
comparison check self-hashes, not signer authenticity, chronology or freshness.
Re-run signed intake when current evidence is needed. No result proves all bugs
are absent, verifies production behavior, or authorizes a deployment.

See [contract format](DEEP_AUDIT_INGESTION.md), [decisions and commands](DEEP_AUDIT_DECISIONS.md),
[engine considerations](DEEP_DEFECT_RESEARCH.md), and
[graph/comparison verification](DEEP_AUDIT_LOOP_VERIFICATION.md).
