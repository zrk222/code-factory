# Code Factory 0.30.0

## Plan-to-Proof Review

Code Factory 0.30.0 adds `factory plan verify`: a deterministic review of a
strict, human-approved agent plan against the exact changed paths, declared test
paths, review tiers, and current Diff-to-Proof facts.

It writes a content-addressed **Proof Debt** artifact for:

- changed paths that were not approved in the plan;
- declared test paths that have not changed;
- deep work that needs a named reviewer; and
- source claims that do not have evidence.

The command produces review obligations only. It does not execute tests, read
agent transcripts, call a model or provider, edit source, change branch
protection, approve, merge, publish, deploy, sign, or claim production
readiness.

```powershell
pip install factoryline-code-factory==0.30.0

factory plan verify `
  .factory/agent-plan.json `
  --root . `
  --base origin/main `
  --out artifacts/plan-proof-review.json `
  --proof-debt-out artifacts/proof-debt.json
```

The plan envelope is strict. It rejects unknown fields, duplicate IDs and
paths, absolute or escaping paths, and a deep review tier without a named
review owner. A matching plan does not mean a passing test, a secure runtime,
or a merge approval.

## GitHub and CodeRabbit interoperability

The optional same-repository GitHub workflow now selects Plan-to-Proof Review
when `.factory/agent-plan.json` exists. It writes one commit-bound,
**neutral** advisory Check and one stable walkthrough comment. If no plan is
present, it retains the existing Diff-to-Proof Review behavior.

Use it with CodeRabbit or another AI reviewer: those tools can contribute
suggestions, while FactoryLine reports deterministic scope and evidence gaps.
Neither a vendor account, provider credential, model comment, nor the neutral
Check becomes FactoryLine proof. The workflow ignores fork pull requests and
does not use `pull_request_target`.

## Enterprise and design-review lanes

The new [Teams and Enterprise Operations Manual](ENTERPRISE_TEAMS_OPERATIONS.md)
organizes a supervised operating model for solo builders, professional teams,
and enterprise review: **proposal → Proof Debt → independent evidence → human
decision**. It keeps authority for merges, publishing, credentials, and
external messages with people and their existing controls.

[Prestige Design Review](PRESTIGE_DESIGN.md) is an optional UI-review lane. It
adds a purpose-led design brief and visible artifacts for hierarchy, responsive
behavior, affordances, consistency, and declared design tokens. Its findings
inform human review. It is not a conversion guarantee, accessibility
certification, or production-readiness claim.

## Editors and public surfaces

The VS Code and JetBrains artifacts are updated to **0.8.6** with the same
Plan-to-Proof, Proof Debt, enterprise, and design-review explanation. They stay
local-first and confirmation-bound. Marketplace publication remains a separate
target-specific gate; a GitHub artifact is not a claim of Marketplace approval.

Read the [release channel guide](RELEASE_CHANNELS.md) for exact target evidence
and the [Plan-to-Proof guide](PLAN_TO_PROOF_REVIEW.md) for the input contract.
