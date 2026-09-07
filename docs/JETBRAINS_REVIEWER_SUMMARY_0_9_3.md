# FactoryLine 0.9.3 — reviewer summary

FactoryLine is a local, review-only proof layer for AI-assisted development.
The 0.9.3 adapter adds seven concrete senior-engineering controls without
granting the IDE, agent, or plugin release authority:

- **Independent execution:** a DSSE-signed observation binds the candidate and
  plan to a runner identity/executable, nonce, cleanup, memory/latency, and
  target/known-bad artifacts. A supervised local observation cannot be labeled
  independent.
- **Real-defect benchmark:** reviewers can supply a bounded buggy/fixed corpus
  and see case-level findings plus per-category precision and recall. A missed
  known defect or failed fix is `BLOCKED`.
- **Dependency-aware proof routing:** a declared DAG produces exact `RUN`,
  `REUSE`, `SKIP`, or `BLOCK` dispositions. Unknown dependency closure,
  side-effecting work, assurance drift, and blocked prerequisites fail closed.
  A shadow command compares incremental and full obligations/findings before a
  skip is reviewed.
- **Independent replay:** `factory senior replay --execute` binds exact source,
  dependency, policy, input, argv, and contract digests to a fresh temporary
  workspace and child invocation with a secret-free environment. The receipt
  explicitly does not claim kernel/container isolation.
- **Executable repair comparison:** `factory senior repair --execute` keeps the
  original failing leg, repaired leg, and negative controls together. A repair
  is not a pass if the original did not fail or a negative control was weakened;
  changed expectations require a named reviewer and reason.
- **Evidence reuse explanation:** `factory senior reuse` compares policy,
  dependencies, toolchain, environment, receipt, and changed-input fingerprints.
  Unknown facts route to `RUN`; side effects route to `BLOCK`.
- **Failure briefing:** `factory senior brief` turns a failed receipt into
  `what broke`, affected scope, reproduction, next fix, uncertainty, and linked
  evidence so a reviewer can act without reconstructing the run from chat.

Every result is bounded JSON with a digest and `authority: none`; all adapters
remain review-only. Replay and repair execute only after explicit `--execute`
and do not access credentials, upload source, publish, deploy, or approve
releases. The human reviewer retains the final decision.
