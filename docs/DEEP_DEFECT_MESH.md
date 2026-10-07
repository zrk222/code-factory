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


## Failure playback, pause and resume

Authorized `factory deep-audit scan` runs retain their event chain under
`.factory/deep-runs/<run-id>/`. Every observed lane failure and run gap is recorded
as `failure_recorded`, with its error code, candidate/manifest binding, lane,
resolution guidance and available bounded execution facts. Findings retain their
own `finding_observed` events. Captured raw stdout/stderr and credentials are not
copied into playback; process hashes and validated worker bundles remain evidence.

```text
factory deep-audit playback --root . --run-id <id> --after 0 --limit 100 --json
factory deep-audit pause --root . --run-id <id> --json
factory deep-audit scan --root . --manifest <manifest> --manifest-sha256 <sha> --authorization <fresh-authorization> --trust-root <trust> --trust-root-sha256 <sha> --resume <id> --json
```

Playback verifies the stored event chain and pages up to 500 events. It never
executes recorded commands. Pause requests cooperative termination of the active
worker; the runner confirms container cleanup before recording `PAUSED`. A
request alone is not proof of a stopped process. Resume creates a linked new run,
rechecks the old event chain, candidate and manifest, validates authorization,
and reruns lanes rather than trusting old successes. A running parent cannot be
resumed. Source changes require a new plan, not resumption of stale evidence.

This lifecycle covers CF-owned isolated deep-audit executions. Legacy receipt
imports, other applications' failures and abrupt power loss are not observed by
this runner. Local self-hashes detect inconsistent records; they are not signatures
or release approval. Disk failure can prevent recording and remains an operator
error, not a successful audit.


### Detection accuracy acceptance target

Detection precision and recall must each reach at least 99.5% on independent,
held-out evaluations for the applicable audit categories before making that
accuracy claim. Report TP, FP, FN, TN, sample counts and confidence intervals
separately by category. A name-based test-intent attribution score or source
quality grade is not detection accuracy. Missing external evaluation is NOT_RUN;
public development cases passing are regression evidence, not proof of
99.5% generalization. Preserve the verifier-only holdout boundary in HOLDOUT.md.
