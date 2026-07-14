# Launch Kit

Copy-ready public launch material for Code Factory and WizeMe.APP. Keep every
claim inside the linked artifact or receipt. Invite independent feedback; never
ask for votes, stars, or reviews.

## Code Factory: Product Hunt Maker Comment

> I made Code Factory because AI-assisted code is fast to produce and hard to
> trust. It is a local, open-source five-part workflow that turns intent into
> explicit specs, challenges whether tests prove behavior, compiles recurring
> decisions into deterministic code, checks design-token contracts, and joins
> the resulting evidence into reviewable receipts.
>
> The proof I care about most is not that a gate exists, but that it notices
> when the gate is sabotaged. For example, `factory verify-policy` deletes or
> inverts release rules and requires the evaluator to fail; otherwise it reports
> `HOLLOW_POLICY`.
>
> This is local tooling, not a hosted platform and not a substitute for human
> judgment. The goal is a better starting point for review: artifacts that say
> what ran, what was proven, and what remains unproven.
>
> I would love feedback on one question: what would you need to prove before
> allowing an AI-generated change into a production repository?

## WizeMe.APP: Product Hunt Maker Comment

> WizeMe is built around a simple rule: memory claims should carry their
> measurement boundary. Our first full LoCoMo end-to-end baseline is public:
> **69.44% J-score**, **68.63% official-style token-F1**, **1,986 of 1,986
> rows**, and **zero errors**.
>
> The receipt names both model roles: DeepSeek V4 Flash answered and Grok 4.5
> was the configured judge. That separates answering from judging; it does not
> establish a universal model ranking or make this an external SOTA claim.
>
> This is a standalone verified baseline, below WizeMe's 75% promotion
> threshold. We are publishing it anyway because the number is more useful when
> its scope, errors, and limits are visible.
>
> The feedback I want most: which failure mode would make you distrust a memory
> system in production, even when its aggregate benchmark score looks good?

## LinkedIn: Code Factory

> AI coding is fast. Verification is the bottleneck.
>
> I released Code Factory, an open-source local workflow for making
> AI-assisted software work reviewable and reproducible.
>
> It has five independent pieces:
>
> - SpecLine turns intent into explicit contracts.
> - ForgeLine challenges whether tests prove behavior.
> - Harness Software Factory compiles recurring decisions into deterministic
>   code.
> - Prestige checks design-token contracts.
> - FactoryLine links the resulting evidence into receipts.
>
> The point is not to bypass engineering judgment. It is to give reviewers
> evidence that a gate actually enforces something. A policy rule that can be
> deleted without changing the result is not policy; it is `HOLLOW_POLICY`.
>
> Code Factory is local, installable, and MIT/Apache licensed:
> https://github.com/zrk222/code-factory
>
> The question I am working on: what would you want proved before trusting an
> AI-generated change in production?

Attach `docs/assets/factory-editor-control-room.svg`. It reflects the shipped
editor adapters without copying stale test counts into a launch post.

## LinkedIn: WizeMe.APP

> Memory systems should publish the boundary around their numbers, not just the
> number.
>
> WizeMe's first clean full LoCoMo end-to-end baseline is now public:
>
> - 69.44% J-score
> - 68.63% official-style token-F1
> - 1,986 of 1,986 rows
> - zero errors
> - DeepSeek V4 Flash as answerer; Grok 4.5 as configured judge
>
> This is not a matched gain or an external SOTA claim. It is a standalone
> verified baseline and remains below our 75% promotion threshold.
>
> The result is useful because the receipt states what ran, which models filled
> which roles, and where the claim stops. That is the standard we want memory
> systems to meet.

Link to the published WizeMe receipt:
<https://wizeme.app/locomo-e2e-jscore-verified-baseline.md>.

## Show HN

**Title**

```text
Show HN: A proof-first factory for AI-assisted software work
```

**Submission text**

> I made Code Factory because I wanted a more useful answer than “the agent
> wrote code and the tests passed.” It is a set of local Python CLIs that hold
> an AI-assisted change to explicit contracts, architecture gates, runtime
> checks, mutation challenges, and hash-linked receipts.
>
> The unusual part is proof by sabotage. We mutate or remove the thing that is
> supposed to protect you: requirements, behavioral tests, decision rules,
> design tokens, and release policies. If the evaluator still passes, the tool
> reports the control as hollow instead of treating its presence as proof.
>
> The components work independently, but the base package connects them:
>
> ```bash
> pip install factoryline-code-factory==0.13.0 code-factory-1-spec==0.5.3 code-factory-2-forge==0.10.4 code-factory-3-compile==0.5.4 code-factory-4-design==0.7.3
> factory doctor --strict --json
> ```
>
> It is local, MIT/Apache licensed, and does not replace code review. I would
> especially value criticism from people maintaining existing repositories:
> where would this add useful evidence, and where would it merely add ceremony?
>
> https://github.com/zrk222/code-factory

## Reply Bank

**“Is this just CI?”**

> CI runs checks. Code Factory also challenges the checks themselves and stores
> the result as a receipt. A green check that cannot fail for the intended
> reason is not useful evidence.

**“Can I use it with an existing repository?”**

> Yes. `forge adopt` writes a reviewable baseline for an existing repository;
> it does not require a greenfield scaffold. The first adoption should be small
> and reversible so the team can measure overhead before expanding use.

**“Does it replace code review?”**

> No. It makes review more concrete by showing what was checked, what was
> challenged, and what still needs a person to judge.

**“Are the benchmark results SOTA?”**

> No. WizeMe's published LoCoMo result is a standalone verified baseline. Its
> receipt names the task, models, metrics, complete row count, zero-error run,
> and the 75% promotion threshold it has not crossed.

## Launch-Day Checklist

1. Publish the maker comment when the Product Hunt listing becomes live.
2. Share the direct Product Hunt link and invite people to read or comment,
   never to vote.
3. Reply promptly with specific, non-defensive answers for the first four hours.
4. Post the Show HN only when the install commands and live demo links are
   working.
5. Record Product Hunt dashboard views, comments, GitHub traffic, PyPI downloads,
   and inbound issues as separate measures. Do not convert them into a single
   “traction” number.
