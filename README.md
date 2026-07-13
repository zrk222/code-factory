# code-factory

[![CI](https://github.com/zrk222/code-factory/actions/workflows/ci.yml/badge.svg)](https://github.com/zrk222/code-factory/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/factoryline-code-factory.svg)](https://pypi.org/project/factoryline-code-factory/)
[![Python](https://img.shields.io/pypi/pyversions/factoryline-code-factory.svg)](https://pypi.org/project/factoryline-code-factory/)

> Most CI proves that code passes. Code Factory first proves that its gates
> reject deliberately sabotaged builds.

Run `factory` with no arguments for a compact live view of installed bricks,
local proof counts, and the next valid commands. This agent-first home view
avoids a separate help/discovery turn while keeping `--help` available everywhere.

```mermaid
flowchart LR
    A["Intent / PRD"] --> B["Real build + gates"]
    A --> C["Proof-by-sabotage challenges"]
    C --> S["Spec mutations"]
    C --> F["Empty stubs"]
    C --> H["Decision-rule mutations"]
    C --> D["Hidden or broken UI"]
    C --> I["Trace tampering"]
    B --> P["Factory Passport"]
    S --> P
    F --> P
    H --> P
    D --> P
    I --> P
    P --> G["GitHub summary + badge + Mermaid + attestations"]
```

> New: PRD-to-app building. Factoryline can now turn a PRD or prompt into a
> full-stack starter repo, then hand it to the same gated, receipted factory
> flow that powers proof-carrying PRs.

![PRD-to-App Factory](docs/assets/prd-to-app-factory.svg)

**A code factory built like Lego.** Five small, independent, open-source pieces that
snap together into one assembly line: describe a feature in plain language, and the
line checks it for ambiguity, builds it, runs a gauntlet of gates, actually *runs*
the finished code to watch it behave, compiles any decision logic into permanent
zero-cost code, and ships it — with a receipt at every step.

Each piece is a separate repo you can install and use on its own. This repo is the
**baseplate** (`factory`) that lines them up. It depends on none of them.

## Workflow at a glance

```mermaid
flowchart LR
    A["Plain-language intent"] --> B["1 SpecLine: clarify and lock the spec"]
    B --> C["2 ForgeLine: build through gated phases"]
    C --> D{"What changed?"}
    D -->|"Business decision logic"| E["3 HSF: compile deterministic artifact"]
    D -->|"User-facing UI"| F["4 Prestige: design-quality gate"]
    E --> G["Receipts and signed artifacts"]
    F --> G
    C --> G
    G --> H["Ship with evidence"]
```

Use the numbered repos like Lego bricks: start with the baseplate, add the spec
brick when intent is fuzzy, add the forge brick when you want a state machine,
add the compile brick when decisions must be deterministic, and add the design
brick when the shipped thing has a user interface.

```
intent -> [1-spec] -> spec + strict contract -> handoff
                                                   |
          [2-forge] <---- tasks / plan <----------+
              |  architect -> build -> gates -> smoke -> ship
              |-> if UI -> [4-design] design-quality gate
              +-> if decision table -> [3-compile] -> deterministic artifact
```

## The five pieces

| Repo | pip install | CLI | What it does |
|---|---|---|---|
| **code-factory** (this) | `factoryline-code-factory` | `factory` | the baseplate — snaps the bricks together, meters cost |
| **code-factory-1-spec** | `code-factory-1-spec` | `specline` | kills ambiguity *before* the AI writes code (anti-drift input contract) |
| **code-factory-2-forge** | `code-factory-2-forge` | `forge` | the assembly line: architect -> build -> gates -> **runtime smoke** -> ship |
| **code-factory-3-compile** | `code-factory-3-compile` | `hsf` | compiles a decision *once* into boring code that runs forever at zero AI cost |
| **code-factory-4-design** | `code-factory-4-design` | `prestige` | design-quality gate, for when what you ship has a face |

Numbered so the assembly order reads at a glance. Install one, some, or all.

The baseplate's PyPI distribution is named `factoryline-code-factory` because
PyPI reserves the more generic `code-factory` name. The repository and the
`factory` command deliberately keep the simpler Code Factory identity.

## Enterprise knowledge activation

Code Factory treats agent instructions as **Atomic Knowledge Units (AKUs)**:
small, high-density, validated units of institutional knowledge. The goal is to
move from "retrieve a long doc and hope the agent interprets it" to "activate the
right procedure, tools, governance, and validators at the exact step of work."

See [AKU_STANDARD.md](AKU_STANDARD.md) for the enterprise schema and how each
brick maps to codification, compression, injection, and validation.

## Quick start

```bash
pip install factoryline-code-factory==0.10.3 code-factory-1-spec==0.5.0 code-factory-2-forge==0.9.1 code-factory-3-compile==0.5.1 code-factory-4-design==0.7.1
```

## Identity-signed receipts

Authenticate any existing factory receipt with Sigstore's keyless OIDC flow:

```bash
pip install "factoryline-code-factory[sigstore]"
factory receipt sign .factory/receipts/<receipt>.json
factory receipt verify .factory/receipts/<receipt>.json \
  --cert-identity "https://github.com/OWNER/REPO/.github/workflows/WORKFLOW.yml@refs/heads/main" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com"
```

Verification binds the exact receipt bytes to the expected signer identity and
issuer. Unsigned receipts remain readable but report `UNSIGNED`, never
`VERIFIED`. See [Signed Factory Receipts](docs/SIGNED_RECEIPTS.md) for the CI
workflow, expected JSON, failure behavior, and honest scope boundary.

## Local control-plane foundation

The control-plane surface adds tenant-scoped evidence, explicit role
authorization, independent human approvals, and a hash-linked audit stream:

```powershell
factory control init --db .factory/control.sqlite3
factory control evidence-put receipts/build.json --db .factory/control.sqlite3 `
  --tenant acme --subject ci-runner --roles operator
factory control audit-verify --db .factory/control.sqlite3 `
  --tenant acme --subject auditor --roles viewer
```

See [docs/CONTROL_PLANE.md](docs/CONTROL_PLANE.md) for the approval workflow
and exact boundary. This is a deterministic local foundation for future hosted
SCM, SSO/SCIM, and evidence-store adapters; it does not claim to be a hosted
multi-tenant service.

## Enterprise Receipt v2 Foundation

The optional enterprise extra adds an offline-verifiable DSSE envelope with an
Ed25519 signer identity, signed policy bundles, and signed revocation lists:

```bash
pip install "factoryline-code-factory[enterprise]"
factory enterprise keygen --out-dir .factory/keys --keyid ci-main \
  --identity "https://github.com/OWNER/REPO/.github/workflows/proof.yml@refs/heads/main" \
  --issuer "https://token.actions.githubusercontent.com"
factory enterprise receipt-seal receipt-v2.json \
  --private-key .factory/keys/ci-main.private.pem --keyid ci-main \
  --identity "https://github.com/OWNER/REPO/.github/workflows/proof.yml@refs/heads/main" \
  --issuer "https://token.actions.githubusercontent.com" --out receipt.dsse.json
factory enterprise verify receipt.dsse.json --trust-root .factory/keys/trust-root.json
```

Verification is local and fail-closed. It checks the DSSE signature, exact
payload digest, trusted key id, identity, issuer, policy digest, and supplied
revocation list without contacting a service. v1 receipts remain readable but
return `LEGACY_UNVERIFIED` in the enterprise verifier. The local control-plane
foundation is documented above; hosted SCM/SSO adapters, OSCAL packs, BBS
credentials, and zkVM proofs remain future roadmap work; see [Enterprise
Receipt v2](docs/ENTERPRISE_RECEIPTS.md).

## Existing Repositories And PRs

Start from inherited code with `forge adopt <feature> --root .`. It writes a
reviewable architecture baseline and, for TypeScript, an explicit mutant
manifest for `forge verify-tests-ts`. FactoryLine exposes the operational
controls professionals need: `factory overhead` reports measured per-gate wall
time, `factory override` writes an owned exception receipt, and `factory ci
init --feature <feature>` writes an opt-in GitHub PR-comment workflow.

factory doctor --strict # versions + required command compatibility
factory plan            # print the assembly pipeline
factory init .          # lay down the shared workspace
factory assemble my_feature   # run the line (skips any missing brick)
factory meter           # receipted cost + savings, computed on YOUR runs
factory rollup my_feature      # aggregate receipt attribution for debugging
factory trace my_feature       # hash-link receipts into a proof bundle
factory verify-trace .factory/traces/my_feature.trace.json
factory replay .factory/traces/my_feature.trace.json --changed smoke/my_feature.json
factory evidence my_feature    # public-safe proof for a PR or release note
factory policy                 # write default policy-as-code thresholds
factory verify-policy --challenge policy.challenge.json # prove every policy rule is enforced
factory optimize-pr --changed specs/my_feature.md --feature my_feature
factory pr-pack my_feature     # reviewer-ready PR_EVIDENCE.md
factory app from-prd PRD.md --out my-app --purpose saas
factory challenge my_feature --trace .factory/traces/my_feature.trace.json
factory passport my_feature --trace .factory/traces/my_feature.trace.json --challenge .factory/challenges/factoryline.json
```

`factory assemble` is resumable and stops at human-owned authoring and approval
boundaries. Its JSON output names `paused_at` and the exact `next_command`; it
does not silently approve architecture or claim unfinished scaffolds are built.

For a concise existing-repository path and a first-run feedback route, see
[First Use On An Existing Repository](docs/FIRST_USE.md). The best contribution
right now is a real repo run, including where the workflow helped or failed.

See [ProofLab and the Factory Passport](docs/PROOFLAB.md) for all five challenge
commands and the generated Mermaid artifact.

For publication order, GitHub release steps, Claude Code/Codex setup, and
launch links, see [PUBLICATION_GUIDE.md](PUBLICATION_GUIDE.md).

## Instant PRD-to-App Builder

`factory app` is the one-shot app-builder workflow: PRD or prompt in,
full-stack starter out, with gates and evidence hooks already attached.
Treat the output as app-shaped starting state that must still move through
SpecLine, ForgeLine, HSF, Prestige, and Factoryline proof before release.

```bash
factory app from-prompt "Build an expense approval app with manager review, audit logs, and policy-based approvals" --out expense-approval
factory app from-prd PRD.md --stack nextjs-fastapi-postgres --purpose healthcare --out prior-auth-portal
```

It generates `app_blueprint.json`, `PRD.md`, frontend/backend/db starter files,
smoke tests, and a workflow guide. The point is not to bypass engineering
judgment; the point is to make the first app-shaped repo appear instantly while
preserving the factory contract.

See [docs/APP_BUILDER.md](docs/APP_BUILDER.md) for the visual workflow,
illustrative readiness model, generated file tree, and follow-up commands.

## PR optimization control plane

Senior review is now a factory surface. `factory optimize-pr` turns a diff into
a bounded hardening plan: changed paths, invalidated gates, design/release
checks, terminal states, and the no-auto-merge authority boundary. It is
deterministic and safe to run before opening or updating a PR.

`factory pr-pack <feature>` writes a public-safe reviewer packet from the
hash-linked trace: what changed, which receipts proved it, what the meter can
honestly measure, and which claims remain scoped. `factory policy` keeps the
team rules visible: hollow-test proof, hollow-validator proof, release
readiness, design purpose, and approval boundaries.

`factory verify-policy --challenge policy.challenge.json` completes the same
mutation doctrine for policy rules: it deletes or inverts every rule and requires
your evaluator to reject the changed policy. A rule that survives is reported as
`HOLLOW_POLICY`; see [Verify Policy](docs/VERIFY_POLICY.md).

![Verify Policy detects a hollow evaluator](docs/assets/verify-policy.gif)

## Why Lego, not a monolith

- **Each brick stands alone.** Install only what you need; a missing brick is skipped, not fatal.
- **Filesystem interop = maximum portability.** Bricks pass work on disk under a shared
  layout. Any IDE, agent (Codex / Claude Code / Cursor), CI runner, or OS that can run a
  subprocess drives the factory. No daemon, no network, no lock-in.
- **No hidden coupling.** The baseplate depends on none of the bricks — it shells out to
  their CLIs. Upgrade or swap a brick independently.

## Honest metering

`factory meter` makes the "saves time and money" claim *yours*, computed from your runs:

- With **no measured runs**, it refuses to print a savings percentage — no number against zero data.
- When modules don't report token usage, it labels the figure a **model**, not a measurement, and says so.
- It prints the **baseline assumption** inline, so no number hides what it's compared against.

Wall-clock time is always measured. Projections are always labeled. Nothing is fabricated.

## Launch Measurement

Use [`scripts/capture_launch_metrics.ps1`](scripts/capture_launch_metrics.ps1)
to save raw PyPI and GitHub traffic observations as JSON receipts. It records
downloads, views, and clones without calling any of them unique users or
attributed conversions; see [Launch Measurement](docs/LAUNCH_MEASUREMENT.md).

## Proof-carrying PRs

`factory trace <feature>` writes `.factory/traces/<feature>.trace.json`: a
deterministic proof bundle over the latest compatible receipts for that feature.
Each trace node records the stage, command, receipt hash, declared artifact
hashes, previous node hash, and attribution summary. The chain head makes receipt
or artifact tampering visible.
`factory rollup <feature>` is the lower-level receipt attribution view for
debugging failed stages; `factory evidence <feature>` is the public-safe view for
PRs, release notes, and README claims.

```bash
factory trace checkout_flow
factory verify-trace .factory/traces/checkout_flow.trace.json
factory rollup checkout_flow
factory risk-diff --changed smoke/checkout_flow.json
factory replay .factory/traces/checkout_flow.trace.json --changed smoke/checkout_flow.json
factory replay .factory/traces/checkout_flow.trace.json --changed smoke/checkout_flow.json --execute
factory attest .factory/traces/checkout_flow.trace.json
factory evidence checkout_flow
```

This is the enterprise Lego layer: the factory can say which guarantee a change
invalidates, which minimum stages must rerun, whether the trace still verifies,
and what public evidence can be shown without leaking raw logs. If a smoke check
is hollow, the public evidence can say `hollow_test`; if the trace was tampered
with, `verify-trace` fails before anyone trusts the PR. `factory attest` exports
unsigned in-toto/SLSA-shaped JSON statements for teams that want supply-chain
evidence attached beside a PR, release, or wheel.

## Spec validator mutation

The assembly line now validates the spec instrument itself:

```bash
specline strict checkout_flow --json
specline verify-validators checkout_flow --json
```

`verify-validators` deletes or inverts one requirement at a time and requires
strict lint to kill the mutant. A requirement whose mutant still passes reports
`hollow_validator`: the spec looked valid, but no validator proved that
requirement mattered. In the default factory chain, this runs after
`specline:strict` and before spec gate signoff or downstream build stages.

## Cross-platform

The baseplate runs on Python 3.10-3.12. The four numbered bricks run on Python
3.11-3.12. Their CI matrices cover Ubuntu, Windows, and macOS.

## License

MIT OR Apache-2.0. Free and open source. Each brick carries both license texts.
Commercial support and integration services available — see [SUPPORT.md](SUPPORT.md).
