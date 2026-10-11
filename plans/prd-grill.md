# Plan: prd-grill
Spec: specs/prd-grill.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Expose a no-write Product Graph analysis and derive a bounded PRD decision frontier.
2. Write source-bound JSON and Markdown clarification artifacts through a local CLI.
3. Test deterministic ordering, deferred dependencies, source immutability, and invalid-input rejection.
4. Update public and editor surfaces with evidence-safe activation copy.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [x] T1 | slice=prd-analysis | files=<=4 | verify=`python -m pytest -q tests/test_prd_grill.py` | Add no-write Product Graph analysis and deterministic PRD Grill artifact generation.
- [x] T2 | slice=prd-cli | files=<=4 | verify=`python -m pytest -q tests/test_prd_grill.py tests/test_product_missions.py` | Add the bounded local CLI with JSON output and confirmation handling.
- [x] T3 | slice=public-surfaces | files=<=4 | verify=`python -m pytest -q tests/test_publication_metadata.py` | Update root, editor, and Marketplace-facing documentation with truthful PRD Grill activation copy.
- [x] T4 | slice=release-proof | files=<=4 | verify=`python -m pytest -q` | Run strict specifications, architecture checks, full suite, and prepare a reviewed PR.

## Accepted goal expansion: guided building with lower-capability agents

Status: research and design accepted into the active goal; implementation and
effectiveness validation remain pending. The historical architect verdict above
applies to the original PRD Grill scope, not this expansion.

### Outcome

Help a beginner describe, build, inspect and repair a useful app through one
CF/FL workflow. Smaller or cheaper coding agents should receive enough explicit
requirements, relevant context and executable feedback to deliver high-quality
results. Whether they match a frontier model must be measured on unseen tasks.
Model confidence, attribution coverage and generated tests are insufficient.

### Research and current foundation

| Product | Documented useful pattern | CF/FL opportunity |
|---|---|---|
| [Lovable planning](https://docs.lovable.dev/features/plan-mode) and [browser testing](https://docs.lovable.dev/features/browser-testing) | Review a plan before building; inspect real interactions in a browser | Bind an approved requirement to each build slice and executed user journey, with before/after evidence |
| [Base44 testing agent](https://docs.base44.com/documentation/managing-app-data/testing-agent) and [test data](https://docs.base44.com/documentation/managing-app-data/testing-your-data) | Select flow tests, inspect activity, fix and rerun; use a separate test database | Reusable isolated app scenarios, evidence-linked repairs and stale-result invalidation |
| [Rork modes](https://docs.rork.com/features/agent-modes) and [platform guide](https://docs.rork.com/swift-vs-react-native/whats-the-difference) | Review screen designs and plans, then build platform-specific apps | Approve visual intent cheaply before coding; preserve shared product requirements with separate platform proof |

These are vendor documentation findings, not hands-on performance comparisons.
Rork's newer platform guide describes Swift, Kotlin and React; its older FAQ
still describes Expo. Detect the actual imported project stack rather than
assuming one from its vendor name. No provider credentials or paid subscriptions
were used in this research.

CF already has `factory mvp`, Studio, PRD clarification, target compilation,
product graphs, value slices, mission decisions, evidence and repair foundations.
Relevant source: `factoryline/studio.py`, `target_compiler.py`,
`product_missions.py`, `prd_grill.py`, `audit_taxonomy.py` and the AppForge
evidence modules. The mission browser contract currently caps a flow at three
clicks; longer journeys need explicit bounded scenario decomposition, not a
claim that this contract proves a full app. Broad guided runtime orchestration,
isolated data setup, cross-platform equivalence and cheaper-model quality are
not established by those existing artifacts.

### Delivery order and acceptance requirements

1. **P0 — One beginner journey in existing Studio.** Connect idea -> Grill-Me
   decisions -> approved PRD -> small build slice -> running preview -> verified
   behavior -> repair. Show the next decision, what works, what failed and what
   was not checked. Preserve revision history and explicit authorization. Prove
   a new operator can complete the journey without knowing factory terminology;
   record actual interactions, elapsed time and help requests.
2. **P0 — Small-agent task compiler.** Give each worker a bounded task packet:
   actor/outcome, accepted examples and counterexamples, relevant source and
   interfaces, permitted changes, dependencies, acceptance commands, budgets
   and stop conditions. Validate schema and candidate hashes before execution.
   Reject scope drift, test weakening and changes that remove their own gate.
   Use installed tools through discovered manifests, not invented commands.
3. **P0 — Independent executable QA.** Assign applicability across static,
   secrets, configuration, dependencies, runtime and fuzz. Require independent
   engine evidence, positive/negative controls, exact candidate/tool bindings,
   parser/timeout/cleanup facts and source accounting. Quality-only findings,
   exploit evidence and missing coverage remain distinct. A missing engine or
   untested platform cannot become a pass through an agent or Jev verdict.
4. **P0 — Real app scenario runner.** Turn approved journeys into bounded
   browser/API/device scenarios with observable oracles. Cover login/logout,
   roles/tenant separation, persistence across sessions, retries, duplicate
   requests, nested failures, timeouts, races and accessible interactions when
   applicable. Create isolated test data and credentials; intercept mail and
   payment effects. Bind screenshots, network/log traces and database effects
   to the build. Include a sabotage that each applicable scenario must catch.
5. **P1 — Evidence-directed repair controller.** Give a cheaper worker only the
   failing invariant, relevant trace, source context and allowed repair scope.
   Cap attempts and spending, retain each failure, invalidate stale results and
   require the repaired candidate to rerun affected gates plus regression
   controls. Repeated failure must change the diagnostic approach or request
   an authorized escalation; never loop on 'try harder'. Preserve pause/resume
   checkpoints and independently review repair before promotion.
6. **P1 — Design and integration rehearsal.** Review screens before coding;
   label mockups as designs rather than running apps. Declare auth, storage,
   mail, payment and backend contracts in plain language, with test/production
   isolation and permission/cost boundaries. Check whether the expected backend
   really stores data, whether secrets reach clients and whether users can
   access each other's records. Rehearse migrations, backup and rollback;
   reverting code does not roll back a database or an external payment.
7. **P1 — Evidence memory and experimental Jev.** Reuse results only for exact
   candidate, inputs, tools, policy and rubric hashes. Invalidate affected
   dependencies after changes; missing graph edges are unknown impact. Jev can
   assess requirement clarity, finding relevance and repair completeness from
   bound evidence, with an explicit insufficient-evidence outcome. Retain raw
   output, rubric/model/version, cost/latency and operator corrections. It does
   not replace executable proof or confirm its own worker's answers.
8. **P1 — Paired quality/cost benchmark.** Freeze task requirements and scoring
   before runs. Compare the same explicitly configured smaller models with and
   without CF/FL, plus a declared frontier baseline. Use independent unseen
   repositories and balanced defective/clean cases across all six lanes and
   real app journeys. Report per-category precision/recall, pass rate,
   regressions, abstentions, escalations, human interventions, total tokens/cost,
   latency and time-to-verified-result with denominators and uncertainty. Count
   all retries and escalations. Hide final labels from workers and judges.
   Do not claim 99.85% accuracy or frontier equivalence until admitted evidence
   supports it; do not weaken the original target to fit current results.
9. **P2 — Portable app handoff and platform proof.** Produce a portable bundle
   of requirements, candidate/build identity, supported/unsupported surfaces,
   test results, outstanding risks, reproduction and rollback instructions.
   Reuse AppForge evidence routes for mobile rather than assuming web checks
   prove Swift/Kotlin/Expo behavior. Import authorized exported repositories
   from builders and audit their actual code/config; no hidden provider API
   scraping or assumed access to hosted backend data.

### Completion boundaries

Reuse existing modules and canonical documentation. Retain the 460 Python-file
ceiling and A>=97.9 requirement. Optimize gate selection only through trusted
selection code; a candidate cannot suppress required worker validation. Each
slice needs CF doctor, a sealed plan, focused execution/negative controls,
hash-bound workflow evidence and independent review. All agent and Junie
manifests must expose the actual installed capabilities and recovery protocol.
Final platform previews use Nanna storytelling after full goal verification,
with authentic UI captures and published capability/version read-back.
