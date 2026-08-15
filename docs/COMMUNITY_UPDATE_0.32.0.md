# Code Factory 0.32 community updates

These drafts are intentionally different for each community. Publish only after
the `v0.32.0` release and public package read-backs succeed.

## Product Hunt product update

### Title

Graph Ops can now compare evidence-backed repairs before you touch the code

### Body

I originally built Code Factory for my own work after wasting too many hours on
AI-generated code whose tests passed but whose real behavior failed. I wanted a
way to see what was actually proven, what was only claimed, and where a run
diverged. I am sharing it free because other builders should not have to repeat
that frustration.

Version 0.32 adds **ProofSearch**, a read-only Counterfactual Arena inside Graph
Ops. Give it sealed evidence for several repair candidates and it will:

- reject candidates with failed proofs, surviving mutants, altered evidence, or
  changes outside the approved path slice;
- compare the remaining candidates deterministically by risk, changed lines,
  proof time, and measured usage;
- show why every candidate won, lost, or was rejected; and
- keep **Apply verified repair** locked until a human reviews the winner.

For vibe coding, this is a clear answer to “which AI fix should I trust?” For
professional teams, it is a reproducible repair decision with hash-bound
evidence and explicit authority boundaries.

I also used the open Prestige design skill on the Graph Ops UI. In my own
observation it materially improved the hierarchy, clarity, and polish; the
release records deterministic design checks separately rather than turning
that observation into a conversion claim.

The savings panel reports time, tokens, and cost only when an exact paired
baseline exists. Otherwise it says **Not measured**—because invented ROI is not
proof.

Free and open source: https://github.com/zrk222/code-factory

![Graph Ops Counterfactual Arena](assets/marketplace/graph-ops-proofsearch.png)

## Product Hunt developer discussion

### Title

Should an AI coding tool compare fixes before applying one?

### Body

I built Code Factory after being repeatedly fooled by passing tests around code
that failed in actual use. The time loss and aggravation were the reason I made
the project, and I am sharing it free.

The new experiment in 0.32 is ProofSearch: instead of asking one model to write,
judge, and apply its own fix, Graph Ops compares multiple **supplied** repair
candidates against a sealed proof slice. Failed proofs, surviving mutants,
scope escape, and changed receipt hashes fail closed. The UI explains every
decision and has no code-generation or apply authority.

The UI itself was refined with the free Prestige design skill. My observation
is that it made the control surface materially clearer and more polished; I am
interested in whether that holds up for developers seeing it fresh.

I would value developer feedback on the boundary: what evidence would you need
before a repair recommendation became useful in your own review process?

Repository and working UI: https://github.com/zrk222/code-factory

## Indie Hackers

### Title

I built a repair comparison tool because passing tests kept wasting my time

### Body

I did not start Code Factory because I wanted another AI coding platform. I
built it for myself because I was tired of the same cycle: a coding assistant
made a change, the tests went green, I trusted the result, and the feature still
failed when I actually used it.

That wasted time was worse than the original bug. I had to reconstruct what the
assistant changed, whether the test could ever fail, and which “fix” was the
least risky. The frustration pushed me to bring the whole process under one
proof-first workflow, and I am sharing it free so other builders can avoid some
of that pain.

The latest release adds ProofSearch to Graph Ops. It compares several supplied
repair candidates, rejects anything with failed evidence, surviving test
mutations, or changes outside the approved slice, then explains why the
smallest verified candidate won. It does **not** silently apply the winner; that
decision stays with the person reviewing the work.

I also ran the UI through the Prestige design skill. From my own use, it made a
material difference to the visual hierarchy and readability. That is my
observation, not a made-up conversion statistic, so I would welcome honest
feedback on the screenshots.

Solo builders get a readable answer before accepting an AI fix. Teams get a
hash-bound decision record they can review and reproduce. And if there is no
paired baseline, the dashboard says savings are not measured instead of making
up a percentage.

Code Factory is free and open source: https://github.com/zrk222/code-factory

I would genuinely like to know: what is the most expensive “green test, broken
feature” incident you have had?

## Hacker News / Show HN

### Title

Show HN: Code Factory – compare proof-bound repairs without auto-applying them

### Text

I built Code Factory for my own use after losing too much time to assistant-
generated code whose tests passed but whose behavior failed in real use. I am
sharing it free.

Version 0.32 adds a deterministic ProofSearch layer. It accepts sealed evidence
for 2–12 repair candidates, rejects failed proofs/surviving mutants/scope escape,
and ranks only eligible candidates. Graph Ops shows the first divergence, exact
proof slice, winner rationale, and every loser reason. The tool has no authority
to generate or apply code, mutate tests, merge, publish, or deploy.

The Graph Ops surface was refined with the open Prestige design skill. My own
observation is that it materially improved clarity and visual hierarchy; the
repository includes deterministic design receipts, but no conversion claim.

It also refuses to invent savings: time/token/cost stay null without an exact
paired baseline.

Repo: https://github.com/zrk222/code-factory
