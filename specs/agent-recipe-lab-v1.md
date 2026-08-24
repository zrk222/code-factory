# Spec: agent-recipe-lab-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Agent Oven shall let a workspace optimize an agent recipe against a tenant-owned evaluation set without exposing secrets, exceeding a declared credit ceiling, or automatically promoting a winner. Convex remains the authoritative control plane. Trusted hosted workers may execute trials but may only report bounded checkpoints and final evidence.

### User roles

- Workspace operators create and start bounded recipe studies.
- Trusted hosted workers claim queued trials and report checkpoints and outcomes.
- Workspace admins or reviewers approve a champion, and the approver must differ from the study creator.
- Workspace viewers inspect redacted study, frontier, and evidence summaries.

### Requirements (EARS)

- When creating one `AGENT_RECIPE_STUDY`, the system shall reject the request unless `trialCount` is an integer of at least 2 trials and at most 24 trials, `studyCredits` is an integer of at least 1 credit and at most 100000 credits, `trialCredits` is an integer of at least 1 credit and at most 10000 credits, `graceCheckpointCount` is an integer of at least 1 checkpoint and at most 5 checkpoints, and integer quality, cost, and latency weights total exactly 100 points.
- When an operator starts a draft study, the system shall return `RECIPE_STUDY_STARTED` with evidence marker `RECIPE_CANDIDATES_GENERATED` after generating deterministic candidate recipe records equal to the declared trial count from the declared model identifiers, retrieval-depth values, memory modes, and authority modes without invoking a model.
- When a trusted worker claims a queued trial, the system shall return `RECIPE_TRIAL_CLAIMED` for exactly one trial and shall reject a second claim for that trial.
- When a worker records one checkpoint, the system shall append exactly one `RECIPE_CHECKPOINT_RECORDED` record containing checkpoint number, integer quality score, cumulative credits, cumulative latency milliseconds, and policy-violation count.
- If a checkpoint reports at least 1 policy violation, the system shall mark that trial pruned and return `RECIPE_TRIAL_PRUNED` with reason code `TRIAL_POLICY_VIOLATION_PRUNED`.
- When a worker completes a claimed trial, the system shall return `RECIPE_TRIAL_COMPLETED` after validating an evidence digest from 16 characters through 120 characters, a quality score from 0 points through 100 points, cost from 1 credit through 10000 credits, latency from 0 milliseconds through 86400000 milliseconds, and policy violations from 0 violations through 100 violations; at least 1 policy violation or 1 violated hard constraint shall make the trial ineligible.
- When an operator finalizes a running study, the system shall reject finalization while any trial is queued or running, compute the non-dominated Pareto frontier over eligible completed trials, select one champion deterministically by the declared weighted score with recipe digest as the tie-breaker, and return `RECIPE_CHAMPION_PROPOSED`.
- If no eligible completed trial exists, the system shall return `RECIPE_STUDY_NO_CHAMPION` with reason code `E_RECIPE_NO_ELIGIBLE_CHAMPION` and shall not create a promotion request.
- When an admin or reviewer approves a proposed champion with its exact recipe digest, the system shall reject self-approval, reject a mismatched digest, persist the independent reviewer identity, and return `RECIPE_CHAMPION_APPROVED` without activating or deploying the recipe.
- When a viewer requests a study summary, the system shall return `RECIPE_STUDY_REDACTED` without evaluation-set object references, worker identifiers, creator identities, or raw provider credentials.
- When the web assembly surface renders, the system shall expose `RECIPE_LAB_SIX_STAGES` with six ordered stages labeled Use case, Evaluation set, Search space, Guardrails, Optimize, and Review, explain human-controlled activation, and provide a primary action target at least 44 pixels high.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Invalid study bounds are rejected
  Given trialCount is 1 trial, studyCredits is 0 credits, trialCredits is 0 credits, or graceCheckpointCount is 0 checkpoints
  When an operator creates AGENT_RECIPE_STUDY
  Then the request is rejected before any study is stored
  And valid quality, cost, and latency weights total exactly 100 points

Scenario: Operator starts a bounded recipe study
  Given a study with 6 maximum trials and a 300-credit ceiling
  When the operator starts the study
  Then RECIPE_STUDY_STARTED contains exactly 6 deterministic candidate recipe records
  And RECIPE_CANDIDATES_GENERATED is recorded
  And no model or external tool has been invoked

Scenario: Worker claims one queued trial once
  Given 1 queued recipe trial
  When a trusted worker claims that trial
  Then RECIPE_TRIAL_CLAIMED is returned for exactly 1 trial
  And a second claim is rejected

Scenario: Worker records one bounded checkpoint
  Given 1 claimed trial
  When the worker reports checkpoint 1 with integer quality, cumulative credits, cumulative latency milliseconds, and policy-violation count
  Then exactly 1 RECIPE_CHECKPOINT_RECORDED record is appended

Scenario: Unsafe trial is pruned
  Given a claimed trial with 2 grace checkpoints
  When its third checkpoint reports 1 policy violation
  Then RECIPE_TRIAL_PRUNED is returned with TRIAL_POLICY_VIOLATION_PRUNED
  And the trial cannot become the champion

Scenario: Worker completes an eligible trial
  Given 1 claimed trial with no violated hard constraint
  When the worker reports a 16-character evidence digest, 80 quality points, 12 credits, 500 milliseconds, and 0 policy violations
  Then RECIPE_TRIAL_COMPLETED is returned
  And the trial is eligible

Scenario: No eligible trial closes without a proposal
  Given every terminal trial has at least 1 policy violation
  When the operator finalizes the study
  Then RECIPE_STUDY_NO_CHAMPION is returned with E_RECIPE_NO_ELIGIBLE_CHAMPION
  And no promotion request is created

Scenario: Pareto champion requires independent approval
  Given all trials are terminal and at least 1 eligible trial exists
  When the operator finalizes the study
  Then RECIPE_CHAMPION_PROPOSED identifies a Pareto-frontier recipe digest
  And the creator cannot approve that champion
  And a distinct admin or reviewer can return RECIPE_CHAMPION_APPROVED

Scenario: Viewer receives a redacted study summary
  Given a stored evaluation-set object reference, worker identifier, creator identity, and provider credential
  When a viewer reads the study summary
  Then RECIPE_STUDY_REDACTED is returned
  And none of those four sensitive values is returned

Scenario: Novice sees the complete six-stage assembly
  Given the Agent Recipe Lab is displayed
  When the user reads the ordered stages
  Then RECIPE_LAB_SIX_STAGES exposes Use case, Evaluation set, Search space, Guardrails, Optimize, and Review in that order
  And the primary action is at least 44 pixels high
  And the page explains human-controlled activation
```

## SHOULD

- Show completed, pruned, queued, and running counts beside the credit ledger.
- Explain the champion using quality, cost, latency, trust, and evidence labels rather than a single opaque score.
- Keep the search-space form novice-friendly while preserving exact values in an advanced summary.

## COULD

- Add TPE or ASHA proposal services in a hosted worker after deterministic candidate generation has production evidence.
- Export a signed qualification report after a champion is independently approved.

## MUST NOT

- Do not execute optimization inside a Convex mutation.
- Do not store evaluation data, provider keys, prompts, or database credentials in recipe-study records.
- Do not tune directly against production traffic.
- Do not activate, deploy, or publish an approved champion automatically.
- Do not describe modeled scores as observed production outcomes.

## Failure matrix

| Failure | Required result |
| --- | --- |
| Search space empty or outside bounds | `E_RECIPE_SEARCH_SPACE_INVALID` |
| Weight total differs from 100 | `E_RECIPE_WEIGHTS_INVALID` |
| Study or trial credit ceiling crossed | trial state is pruned |
| Trial includes policy violations | ineligible and never champion |
| Finalization has non-terminal trials | `E_RECIPE_TRIALS_INCOMPLETE` |
| No eligible candidate | `E_RECIPE_NO_ELIGIBLE_CHAMPION` |
| Creator approves own champion | `E_RECIPE_SELF_APPROVAL_FORBIDDEN` |
| Champion digest differs | `E_RECIPE_CHAMPION_DIGEST_MISMATCH` |

## Evidence boundary

Passing tests prove deterministic candidate construction, checkpoint pruning, Pareto selection, authorization, redaction, and UI accessibility. They do not prove provider inference quality, production cost savings, or externally executed optimization until a trusted worker adapter supplies real evidence.
