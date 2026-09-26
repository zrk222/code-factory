---
name: expertise-agent-workflows
description: Route supplied-record business reviews to Earnie vendor value, Cluso account impact, or Surely portfolio watch with explicit evidence and action boundaries.
metadata:
  short-description: Evidence-bound business review workflows
---

# Expertise business review workflows

Use the workflow named by the MCP packet's `workflow` field. The MCP bridge
selects a review contract; Muse performs an advisory analysis from records the
user supplied or explicitly authorized. If required scope or evidence is
missing, return **blocked** and name what is missing. Do not fill gaps with
assumptions, turn proximity into impact, or imply that a local tool fetched
data from Expertise.ai.

Keep source identity, observation date, provenance, and uncertainty beside each
fact. Separate confirmed facts from claims, analysis, items to verify, and
blocked evidence. Every complete result remains advisory and requires human
review. Do not contact a customer or vendor, change a CRM, negotiate, approve,
issue a payment, alter a portfolio, or take other external action.

## Earnie: vendor value review

Choose exactly one supplied playbook:

- `renewal_vendor`: contract terms, pricing history, expiration, current and
  benchmark annual cents.
- `quote_margin`: quote lines, cost basis, margin threshold, integer price/cost
  cents and floor basis points.
- `collections`: aged receivables, invoice receipts, communication log, overdue
  and disputed cents.
- `capacity_to_cash`: utilization, rate card, milestone, available minutes and
  billable rate cents/hour.
- `ai_spend`: usage sessions, token counts, model rates, total cost micros and
  execution count.

Use only evidence supplied or authorized for this task. If a required metric or
record is absent, block the recommendation. Explain arithmetic in integer
units, mark estimates conditional on supplied inputs, and never claim realized
savings.

## Cluso: account impact review

Establish tenant, source system, workspace, account reference, authorization
basis, and date window before analysis. If any are missing, block and request
only the missing scope. A connected badge is not evidence; use a connector only
when separately configured, approved, and returning actual tenant-bound data.

Return the account scope, date window, supported signals, contradictions,
unknowns, smallest useful verification step, and accountable human owner. Do
not infer account health, churn, revenue, or customer intent from silence or
stale data.

## Surely: portfolio watch

Confirm the authorized account/site scope, U.S. commercial locations, review
window, source timestamps, and provenance. Use official event evidence only
when directly available. Proximity is context, not proof that a site was
disrupted. Keep impact **unknown** unless an attributable site operator or
authoritative operational record confirms it. Limit an action-card shortlist
to five, identify a human owner, and state the next verification step.

The earlier Expertise custom-MCP calls failed with `account_mismatch`. Treat
that connector as unavailable until an approved read returns real tenant-bound
data. Do not turn connection status or an empty response into a clean portfolio.
