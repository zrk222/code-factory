# Adversarial task approval

Agent Oven separates producing work from authorizing it. Every assurance run receives an offline, deterministic review under `adversarial-approval.v1` before an approval can finish.

## What can complete automatically

Only `read` or `analyze` work in the `test` environment can be automatically approved, and only when the action digest matches, worker and approval identities differ, admitted cost is at most 100 cents, at least three proof-bearing gates pass, two evidence digests are bound, and no gate is blocked.

## What always requires a person

Code changes, external sends, deployments, deletion, payments, credential access, and every production action return `human-required`. A reviewer must be authenticated, distinct from the worker and approval agent, and act within the review's 24-hour validity window.

## Proof Delta

Proof Delta compares current content-addressed evidence to the most recent comparable review. It lists reused, new, and missing evidence so reviewers can focus on change. It does not replay a decision, expand capability, or treat memory as authority. The product reports exact evidence counts; it does not report time or token savings without paired measured receipts.

## Current deployment boundary

The local demonstration creates six illustrative gate records. Those records prove the approval mechanics and UI, not a production repository outcome. Production use must replace them with real Code Factory receipts admitted by a trusted runtime worker. Repository tests cannot supply deployment identity, provider secrets, tenant configuration, or live worker evidence.
