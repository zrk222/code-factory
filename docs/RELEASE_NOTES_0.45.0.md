# Code Factory 0.45.0 — know what actually happened

AI can produce code, tests, and confident explanations in minutes. The hard
part begins after that: did the test have a real failure mode, did the agent
stay inside the agreed scope, and did the user who paid actually receive—and
later lose—the right access?

Code Factory 0.45.0 turns those questions into reviewable local evidence.

## If you build alone

Start with one command:

```bash
factory first-proof --root .
```

It demonstrates whether a test can reject a deliberately broken condition.
You get a local receipt and the next review step, not another AI opinion. Your
code stays local, and you decide what happens next.

## If you build with a team

Wrap an agent run, bind the actual file delta and human-confirmed intent, run
independent validators, and keep the evidence hashes. Proof Review puts the
riskiest item first; Graph Ops shows the evidence path; Agent License and
policy gates make autonomy depend on verified history rather than enthusiasm.

The result is a calmer handoff: the team can see what changed, what was proved,
what remains unknown, and who still owns approval.

## If you build SaaS

`factory saas verify` follows one promise all the way to permission:

**OAuth/OIDC identity → tenant and role → checkout → verified webhook →
entitlement → feature access → cancellation, refund, expiry, or revocation.**

It works from normalized local evidence, not a Clerk-specific integration.
Clerk, Auth0, Okta, Microsoft Entra ID, Amazon Cognito, Supabase, Firebase, and
other standards-compliant providers use the same contract. Missing evidence,
duplicate or out-of-order events, bad issuer/audience binding, access without
entitlement, stale access after cancellation, and promise drift all block
green. Raw tokens and secrets are rejected.

## If you operate a platform or enterprise team

The release also brings together tenant-bound evidence operations, immutable
receipts, required-check routing, deterministic policy compilation, metadata
integrity, RevenueForge, AppForge design contracts, evidence memory, MCP,
WebMCP, and IDE surfaces. These support a controlled pilot; they do not activate
a commercial SLA, certify compliance, settle payments, deploy code, or replace
human release authority.

## Use it where you already work

- CLI and any stdio MCP-capable coding assistant
- Unified Graph Ops and progressive WebMCP
- VS Code / Open VSX 0.8.12
- FactoryLine AI Proof for JetBrains 0.8.19

**Try one honest proof:** install Code Factory, run `factory first-proof`, and
inspect the receipt before you trust the next green check.
