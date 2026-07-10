# Code Factory Mechanics Deep Dive

This note maps the next layer of safeguards, traces, automations, and efficiency
upgrades across the five-piece factory. It separates implemented mechanics from
the next high-leverage improvements so public claims stay receipt-backed.

## System-Level Safeguards

Implemented:

- Per-stage attribution with stable failure classes and concrete evidence.
- Build-time-only refinement state, edit selection, and rejection ledgers.
- Exact Pareto acceptance for refinement: keep one localized edit only when the
  target gate improves and no other gate regresses.
- Factory rollup chooses the earliest failing stage, not the noisiest downstream
  symptom.
- Proof-carrying PR traces hash-link stage receipts and declared artifacts, then
  verify receipt integrity, artifact integrity, stage order, and the H=0 boundary.
- Proof traces can be exported as unsigned in-toto/SLSA-shaped statements for
  release attachment or enterprise ingestion.
- Replay execution is available behind an explicit `--execute` flag and refuses
  to run if `verify-trace` fails.

Best next upgrades:

- Add DSSE/Sigstore wrapping for the current JSON attestation payloads.
- Add replay execution receipts that summarize exactly which minimal rerun
  commands were executed.
- Add a CI matrix job that installs the five packages together and runs a tiny
  cross-module proof project end to end.

## 1. SpecLine

Current strength:

- Requirement-level and function-level attribution makes vague specs and drift
  local instead of global.

Best next upgrades:

- Add spec mutation checks: remove or invert one requirement and prove the
  strict gate notices the missing validator.
- Export AKU validator coverage directly from strict JSON so governance level
  is derived, not hand-labeled.
- Add token-density receipts per packet: tokens used, requirements covered, and
  validators produced.

## 2. ForgeLine

Implemented in the v0.6 pass:

- `TESTS_VERIFIED` state between `ARCH_GATED` and `SMOKED`.
- `forge verify-tests <feature> <ssat>` regenerates the SSAT scaffold in a temp
  root and runs smoke checks against empty stubs.
- Behavioral checks must fail on the stub. Passing on the stub blocks with
  `HOLLOW_TEST`.
- All-exempt or empty manifests block with `HOLLOW_MANIFEST`.
- `must_fail_on_stub` defaults to `true`, so omission never buys leniency.
- Stub identity is tested against the same SSAT scaffold generator that creates
  `SCAFFOLDED`.

Best next upgrades:

- Add a real `forge fill <feature>` state transition so CLI-only users do not
  need an agent or `RunStore` call to mark filled implementation.
- Add `forge trace <feature>` to print the legal next command plus the exact
  receipt files that justify the current state.
- Parallelize reverse-classical checks after correctness is stable.

## 3. Harness Software Factory

Current strength:

- The H=0 artifact boundary is strong: prompt-injection detection, golden
  attribution, receipt-backed meter, and artifact SHA invariance.

Best next upgrades:

- Attach per-rule coverage in golden receipts: which rules were exercised and
  which public claims they support.
- Add a `hsf replay --receipt` command that reconstructs the compile/goldens
  run from receipt metadata.
- Add optional Ed25519 signing as the documented v1 HMAC successor.

## 4. Prestige Design

Implemented in the v0.3 pass:

- New deterministic purpose-fit engine.
- New commands:
  - `prestige purposes`
  - `prestige purpose <file> --purpose <key>`
  - `prestige score <file> --workflow <key> --purpose <key>`
- Purpose profiles:
  - `developer`: concrete proof, docs, CLI/API clarity, GitHub/demo trust.
  - `healthcare`: calm reassurance, privacy, clinician proof, no miracle hype.
  - `fintech`: security, transparent fees/rates, control, compliance cues.
  - `luxury`: restraint, craft, whitespace, fewer louder elements.
  - `marketplace`: bilateral buyer/seller trust, reviews, protection,
    comparison.
  - `saas`: product visibility, integrations, ROI, low-friction activation.
  - `editorial`: narrative rhythm, sources, evidence, satisfying end beat.
- Purpose scoring covers intent clarity, proof fit, visual theme, action
  language, and purpose-specific anti-patterns.

Why this matters:

- Workflows are optimization strategies.
- Purpose lenses are audience psychology and domain fit.
- A page can be visually polished but wrong for its purpose: aggressive scarcity
  on healthcare, vague magic claims on developer tooling, hidden fees on
  fintech, or loud discount language on luxury.

Best next upgrades:

- Add a color-semantics parser that scores palette fit more precisely from
  actual CSS colors.
- Add screenshot-backed visual density checks using Playwright for pages that
  need browser rendering proof.
- Add per-section purpose traces, so the report says where reassurance, proof,
  CTA, and anti-pattern failures occur.
- Add generated design briefs: `prestige brief --purpose healthcare --workflow
  trust` to output a build-ready design contract before markup exists.

## 5. Factoryline

Current strength:

- It stays dependency-light and treats missing modules as skipped studs instead
  of hard failures.

Implemented in this pass:

- The default assembly chain now includes ForgeLine `verify-tests` before
  `smoke`.
- The shared failure-class baseplate recognizes `hollow_test` and
  `hollow_manifest`.
- `factory trace <feature>` writes `.factory/traces/<feature>.trace.json`, a
  hash-linked proof bundle over the latest compatible receipts.
- `factory verify-trace <trace>` detects receipt tampering, artifact tampering,
  chain-head drift, and H=0 metadata leakage into registry artifacts.
- `factory replay <trace> --changed <path>` maps changed files to the minimum
  canonical stages that must rerun before the trace should be trusted again.
- `factory risk-diff` exposes the same invalidated-guarantee map without needing
  a trace file.
- `factory evidence <feature>` prints public-safe PR evidence: trace hash,
  chain head, stage verdicts, failure classes, savings model, and scope limits
  without raw logs.
- `factory attest <trace>` exports in-toto/SLSA-shaped proof statements.
- `factory replay <trace> --execute` verifies the trace before running the
  minimal invalidated stages.
- `.github/workflows/publish.yml` builds, tests, checks, attaches release
  artifacts, and publishes to PyPI through Trusted Publishing.

Best next upgrades:

- Add `factory doctor` to check installed CLI versions, expected commands, and
  whether the five packages are mutually compatible.
- Add generated Mermaid trace diagrams from receipts.
- Attach generated proof traces and attestations beside wheel/sdist assets for
  release-specific factory runs.
