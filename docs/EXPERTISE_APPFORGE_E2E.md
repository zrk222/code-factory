# Expertise.ai + AppForge: end-to-end operating guide

## Ten-second value

Tell the system who the app serves, what users need to accomplish, and how the experience should feel. It produces a reviewable iOS design and monetization workspace, shows what is proven or still unknown, and leaves consequential approval with a human.

## The journey

| Stage | Recognizable action | What the user sees | Stop condition | Recovery |
|---|---|---|---|---|
| 1. Mission | **Describe my app** | Audience, job, desired emotion, brand constraints, and screen goals | Required intent is missing or contradictory | Ask only the smallest unanswered question and show why it matters |
| 2. Direction | **Choose a design** | Two or three materially different directions with trade-offs | No human selection | Preserve drafts and request one explicit choice |
| 3. Storyboard | **Build storyboard** | Mission → tension → guidance → agency → transformation → celebration across every screen and system state | A screen lacks a user goal, primary action, or recovery state | Highlight the exact screen and missing field |
| 4. Design proof | **Review design** | Visual direction, accessibility, SwiftUI design, motion, gestures, performance, and color psychology | A required discipline is unreviewed | Name the discipline, evidence needed, and safe next check |
| 5. Monetization build | **Build purchase lane** | StoreKit, paywall, entitlement-server, privacy, and review artifacts bound to one manifest | Deterministic manifest or safe-lane gate fails | Show the failing declaration and the minimal correction |
| 6. Reality replay | **Check purchase reality** | Seven lifecycle steps marked matched, mismatch, or unknown | Any mismatch or unknown | Identify the exact missing or contradictory observation |
| 7. Negative paths | **Run failure matrix** | Ten failure scenarios with observed evidence status | Any failure or unknown | Run or supply only the named missing scenario evidence |
| 8. Beta evidence | **Open TestFlight inbox** | De-identified feedback grouped by build, environment, device, OS, and journey | Export is absent, malformed, or contains a signed payload | Export an authorized local copy and remove identity or signed payload fields |
| 9. Policy watch | **Check policy drift** | Impact-scoped source changes requiring review | An official-source hash changed or a source is unavailable | Human reviews only the affected rules, apps, and artifacts |
| 10. Continuity | **Use evidence memory** | Unexpired exact-app lessons approved by a named human | Evidence is stale, invalid, cross-scoped, or contradictory | Collect fresh evidence or perform human contradiction review |
| 11. Decision | **Approve or revise** | One summary: what changed, what is proven, what is unknown, and the next safe action | Human approval is absent | Keep all provider actions locked |

## Nanna storytelling, used responsibly

- **Mission:** say what the user came to accomplish.
- **Tension:** name the real obstacle without exaggeration or fear.
- **Guidance:** reveal the information or tool that makes progress possible.
- **Agency:** keep the user's choice clear, reversible where possible, and consequence-aware.
- **Transformation:** show the meaningful state change, not a vanity animation.
- **Celebration:** finish with calm confirmation, evidence, and a recovery path.

Story supports comprehension; it never hides price, renewal, cancellation, risk, system state, uncertainty, or recovery. No false urgency, emotional coercion, or invented proof is allowed.

## One result format everywhere

Before every function runs, show a brief **Action summary**: what will happen, which inputs will be read, which artifacts may be written, and which external actions remain locked. After execution, every stage returns the same six items:

1. **Action summary:** the function just executed, its inputs, its output, and what remained untouched.
2. **Status:** Pass, Partial, Unknown, Fail, Blocked, or Not applicable.
3. **Why:** one plain-language sentence tied to supplied evidence.
4. **Evidence:** build/environment/product bindings and hashes when available.
5. **Next action:** the smallest safe step that advances the work.
6. **Authority:** whether a human decision or external provider action is still required.

## Connect your existing tools

- **IDE or coding agent:** connect to `factory mcp serve --root .` and read RevenueForge, Evidence Memory, AppForge, intent, verifier, and Graph Ops status without granting write authority.
- **Graph Ops browser:** a compatible browser can discover four bounded, read-only WebMCP tools over the authenticated snapshot already on screen.
- **Same mission handoff:** move from assistant to Graph Ops and back using receipt hashes and exact status—not copied prompt claims.

MCP and WebMCP are observation surfaces. They do not approve a design, execute a repair, contact Apple, publish, deploy, read credentials, or grant a connector. See [MCP and WebMCP](MCP_WEBMCP.md).

## Human authority

The workflow may draft, compare, validate, replay, summarize, and recommend. It may not purchase, price, start experiments, send offers, reply to testers, change App Store Connect, deploy, submit, publish, access credentials, or claim Apple approval without a separately authorized authenticated operation.

## Completion definition

Completion means the requested local artifacts exist, deterministic gates pass, unknowns are explicitly preserved, receipts are hash-bound, the user can see the result and next action, and the worktree is tested and clean. It does not mean Apple approval, legal compliance, deployed production behavior, conversion lift, or revenue.
