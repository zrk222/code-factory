---
name: full-stack-ux-harness
description: Build or review substantial full-stack and product-facing UI work with evidence-bound architecture, production, accessibility, interaction, and ethical UX gates. Skip trivial edits and non-product documentation.
---

# Full-Stack Code and UX Harness

Use the repository's architecture and design system as the primary contract.
This skill adds a shared review route; it does not replace native tests,
Prestige visual review, security tooling, or the release owner's decision.

## Before implementation

Record the user task, data and trust boundaries, component/service ownership,
typed API and persistence contracts, state transitions, responsive behavior,
and accessibility requirements. Separate data access, domain logic, state, and
presentation. Define loading, empty, partial, error, recovery, and negative
states before presenting an interactive surface as complete.

For substantial work, create the closed manifest:

```powershell
factory quality-harness template --root . --ui --out .factory/quality-harness/manifest.json
```

Omit `--ui` only when product-facing UI is genuinely outside the approved
scope. The closed check list may not be reduced or expanded by the implementer.

## Implementation standard

- Validate untrusted input at typed boundaries and keep state deterministic and
  local unless sharing is necessary.
- Preserve secrets, least data collection, safe rendering, authorization,
  origin policy, content policy, and explicit failure recovery.
- Measure before adding performance complexity; use appropriate deferral,
  responsive media, pagination, or virtualization when evidence supports it.
- Follow the existing visual tokens or a 4/8-point rhythm, semantic colors,
  readable hierarchy, WCAG 2.1 AA contrast, semantic controls, visible focus,
  logical keyboard order, and screen-reader labels.
- Put the core task first, progressively disclose advanced controls, and show
  immediate acknowledgement or an honest pending state for every action.
- Preserve user agency. Do not use fabricated metrics, reviews, scarcity,
  credentials, urgency, hidden costs, preselected consent, or obstructive exits.

## Evidence and human review

Run the project's native test, type, lint, build, accessibility, security,
performance, and render checks that apply. Attach their non-empty artifacts to
the manifest with approved provenance. An agent-proposed gate remains blocked
until confirmed by a human or trusted source.

One named human must separately record truth, regret, transparency, alignment,
comprehension, and vulnerability judgments with concrete rationales. The agent
must not approve these judgments for its own work. The local name/type fields
are declared metadata, not authenticated identity; consequential workflows must
bind the approval through the repository's trusted identity and receipt system.

Verify the completed manifest:

```powershell
factory quality-harness verify .factory/quality-harness/manifest.json --root . --json
```

`READY_FOR_HUMAN_RELEASE_REVIEW` means only that the declared evidence and
human judgments are complete and hash-bound. It is not certification, measured
conversion impact, security or accessibility proof, deployment authority, or
release approval.
