# GitHub discovery and community launch kit

This kit makes the free, local-first project easier to evaluate and share. It
does not send posts, edit a user's project, collect analytics, buy attention,
or manufacture stars. Treat every public claim as either product behaviour
covered by source/tests or as an explicitly labelled draft.

## Repository first view

Lead with the concrete value that a developer can verify:

> **Catch AI-generated tests that could never fail — before review.** Free,
> local proof for code built with AI makes the next proof gap visible before a
> starter is called production-ready.

The intended next action is one local command:

```powershell
pip install factoryline-code-factory
factory mvp "Build an approval tracker" --root .
factory studio --root .\my-mvp
```

The README then shows actual current Factory Studio captures and one optional
GitHub-star link after the first-run value. It makes no star-count, download,
conversion, productivity, or causal growth claim.

## Repository metadata

Keep the repository About description aligned with the PyPI summary:

> Catch AI-generated tests that could never fail and review AI code with local
> proof.

Use the repository homepage for the live Hugging Face Space. Keep the topic set
focused on real discovery terms: `ai-agents`, `ai-coding-assistant`,
`code-generation`, `developer-tools`, `mcp`, `testing`, `workflow-engine`,
and the supported editor/client ecosystems. Do not add generic hype topics or
claim an integration is available before its target marketplace approves it.

## Client and demo discovery

Make the first click useful for both novices and experienced AI-tool users:

- [Live browser preview](https://zrk222-code-factory.static.hf.space) for a
  no-install product tour.
- [Current product visual set](PRODUCT_VISUALS.md) for the actual local Studio
  path.
- [Cursor and OpenCode MCP setup](AI_CLIENTS.md) for local, read-only proof
  context inside the clients developers already use.
- [PyPI install](https://pypi.org/project/factoryline-code-factory/) for the
  shortest executable path.

Use one of these links per post, with one concrete question or outcome. Do not
paste every channel link into a community thread; the extra links dilute the
action and can look promotional rather than useful.

## Free integration message: AI review plus proof

The useful comparison is not "Code Factory versus CodeRabbit." It is a clear
division of work: an AI reviewer can surface code concerns; FactoryLine makes
the declared proof state explicit. Teams can run both on one pull request
without sharing credentials or treating a model comment as verification.

Use this as a factual, owner-reviewed reply where a developer asks how Code
Factory fits an existing review stack:

```text
Code Factory is not trying to replace the AI reviewer you already use. Its
optional GitHub Proof Review adds one neutral, commit-bound walkthrough of the
changed scope, declared proof gaps, and next action beside normal review
comments. It needs no CodeRabbit account or API and never auto-approves or
merges. The point is to keep suggestions and evidence distinct.

https://github.com/zrk222/code-factory/blob/main/docs/GITHUB_PROOF_REVIEW.md
```

This is a draft for a relevant discussion, not an automated post. Disclose the
maintainer relationship, check the target's rules, answer follow-up questions
from the owner account, and do not solicit votes, reviews, or stars.

## Ethical compounding loop

```mermaid
flowchart LR
    A["Local outcome → reviewable MVP"] --> B["Receipts + Graph Ops reveal proof path"]
    B --> C["Optional post-success Star Code Factory action"]
    B --> D["Optional static output-map attribution"]
    D --> E["A developer may share it in a PR, README, or team message"]
    C --> F["GitHub visitor"]
    E --> F
    F --> G["One-command first run + current product captures"]
    G --> A
```

Every arrow that leaves Code Factory is voluntary. The editor action opens the
repository only when selected. The output map contains a copyable attribution
but does not post it or modify any user file beyond the output map itself.

## GitHub social preview asset

`docs/assets/github-social-preview-1280x640.png` is a 1280×640 crop from the
actual Factory Studio Graph Ops capture. It is source-ready, not proof that a live Open Graph image is configured.

Repository owner handoff:

1. Open **GitHub repository Settings → General → Social preview**.
2. Upload `docs/assets/github-social-preview-1280x640.png`.
3. Save, then inspect a fresh GitHub share/debug view to confirm the live card.
4. Record the public URL and observation time before claiming it is live.

## Community launch drafts — owner submission only

These are drafts, not automated messages. Before submitting, the owner must
review the target's current rules, disclose their connection to Code Factory,
replace any stale release links, and respond personally to questions. Do not
cross-post identical copy, solicit votes, use alternate accounts, or post
again after removal.

Code Factory does not submit, vote on, or coordinate votes. The owner decides
whether to submit a reviewed draft from their own account.

### Show HN

**Title**

```text
Show HN: Code Factory – Catch AI-generated tests that could never fail
```

**Draft body**

```text
I built Code Factory because I wanted a faster way to turn a plain-language
outcome into a local starting state without pretending that generated code is
ready to ship.

The first run is `factory mvp "Build an approval tracker" --root .`. It writes
an app-shaped scaffold plus a source-bound receipt and Mermaid output map.
Graph Ops then shows which requirements have evidence, what remains blocked,
and one fact-derived next action. The local MCP server exposes the same
read-only inspection facts for coding agents.

It is free and open source. It does not upload source, call a starter
production-ready, execute a release, or ask for credentials. I would value
skeptical feedback on the proof model, the generated MVP path, and what would
make the local experience useful in a real team.

Repository: https://github.com/zrk222/code-factory
```

### Show HN follow-up: review-stack integration

Use only in a relevant existing discussion or a new owner-reviewed submission
whose current rules permit it:

```text
I added an optional GitHub Proof Review adapter because I do not think another
AI reviewer is the missing layer. It can sit next to CodeRabbit or any review
tool and adds a neutral check with the exact changed scope, declared proof
gaps, and one fact-derived next action. It does not use a vendor API, import AI
comments as proof, auto-approve, or merge. I would value criticism of that
separation: should review suggestions and deterministic evidence be distinct?

https://github.com/zrk222/code-factory/blob/main/docs/GITHUB_PROOF_REVIEW.md
```

### Indie Hackers

**Title**

```text
I built Code Factory because I kept getting fooled by passing tests
```

**Draft body**

```text
I am the founder/maintainer of Code Factory. I built it after falling into the
same trap in my own work: a coding assistant would generate code, generate
tests, and leave me with green checks. I would move on, then the important path
would fail when I used the feature for real. The tests passed; the thing still
failed.

The narrow goal is not to add another opaque agent. It is to make the proof path
visible: what requirement a change supports, which checks exist, what evidence
is missing, and what needs a human decision next. Code Factory can start a
contained local MVP, produce receipts and a Mermaid output map, challenge
declared controls for hollow behavior, and show a read-only Graph Ops view.
It does not upload source, publish, deploy, discover credentials, or call a
starter production-ready.

It is free and open source because I built it to save my own time and aggravation
first, and I think the problem is common enough to be worth sharing. I would
value blunt feedback from builders and engineering leaders: where would this
actually save you time, and where would it add ceremony without earning its keep?

Repository: https://github.com/zrk222/code-factory
```

For a longer community article, use
[`docs/WHY_I_BUILT_CODE_FACTORY.md`](WHY_I_BUILT_CODE_FACTORY.md). Review and
submit only from the owner account; do not turn the draft into a comment or a
post without an explicit submission request.

## Reddit enterprise-operations lane — candidates, not preapproval

The goal is useful technical discussion, not broad promotion. Check every
target's current rules, pinned threads, and moderator direction immediately
before posting. Use an owner account with clear founder disclosure; prefer a
focused question or the community's dedicated promotional thread.

| Community | Appropriate angle | Current evidence / safe route |
| --- | --- | --- |
| [`r/devops`](https://www.reddit.com/r/devops/) | CI evidence, local proof reuse, guarded release boundaries, and team review | A current weekly self-promotion thread was observed on 2026-08-03. Use that thread only; state founder affiliation and ask for implementation feedback. |
| [`r/platformengineering`](https://www.reddit.com/r/platformengineering/) | Developer-platform golden paths that do not hide proof or grant deploy authority | A dedicated monthly self-promotion thread is documented, but the evidence is old. Recheck pinned posts before commenting; never use a standalone pitch unless moderators explicitly permit it. |
| [`r/sre`](https://www.reddit.com/r/sre/) | What evidence should exist before an AI-assisted change can be trusted in operations | Relevant community, but no current promotional permission is established by this kit. Use a technical discussion only after current rule review or moderator approval. |
| [`r/kubernetes`](https://www.reddit.com/r/kubernetes/) | How teams keep AI-generated delivery artifacts inspectable and evidence-bound around cluster workflows | The community's published guidance disfavors low-effort self-promotion and requires clear commercial affiliation. Do not post a product pitch; ask moderators first or contribute a self-contained technical discussion with disclosure. |

Suggested `r/devops` thread comment:

```text
Disclosure: I maintain Code Factory, a free local-first project. I built it
around a narrow question: what evidence should an AI-assisted change carry
before a team treats it as reviewable? It can create a contained MVP, keep the
receipt and Mermaid artifact map local, and expose a read-only Graph Ops view;
it does not publish or deploy. I would value feedback on whether this proof
model fits your CI/review workflow and what evidence is missing.

https://github.com/zrk222/code-factory
```

Do not use the Reddit list as a claim that a post is permitted. The `r/devops`
weekly thread observation and the `r/platformengineering` monthly-thread rule
are only routing hints; the current pinned thread and rules control. The
`r/kubernetes` route is deliberately conservative because its guidance
requires valuable discussion and affiliation disclosure.

## Measurement boundary

Track each public action separately and label it as `draft`, `submitted`,
`published`, `removed`, or `not_observed`. GitHub stars, Marketplace downloads,
traffic, external referrals, and product savings are different measures. Do
not infer any one of them from the others or claim attribution without a
source-specific receipt.
