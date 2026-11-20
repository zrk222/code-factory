# FactoryLine 0.8.19 — JetBrains reviewer summary

This is a concise map from common IDE and Marketplace review concerns to the
candidate's shipped behavior and local evidence. It describes the candidate;
it is not a claim of Marketplace approval or a diagnosis of an IDE.

## The one-minute reviewer story

A developer signs in successfully, pays successfully, and still lands in the
wrong tenant without the feature they bought. Each screen looked green; the
journey was broken between screens. FactoryLine 0.8.19 gives that developer two
plain choices inside the IDE: **Verify SaaS journey** from reviewed, local JSON
evidence, or **View SaaS status** from the latest receipt. It then shows what is
proven, what conflicts, and what is still unknown—without receiving a token,
contacting a provider, changing an entitlement, or claiming the release is safe.

That is the candidate's purpose: make the gap visible while the developer still
has control. The same supervision boundary applies to IDE-health observations,
AI-authored diffs, intent, and engineering decisions. A human always chooses
whether to run the local command and what to do with its evidence.

| Review concern / user impact | FactoryLine response | Proof or reference |
| --- | --- | --- |
| SaaS login, payment, and feature access can silently disagree across providers. | **SaaS Reality** offers explicit **Verify SaaS journey** and **View SaaS status** controls. Verification uses workspace-local contract/evidence JSON and writes a hash-bound local receipt covering OAuth/OIDC issuer/audience, tenant/role binding, checkout, verified webhook, entitlement, access, and revocation. Unknowns block green. It never contacts a provider or handles credentials. | `factoryline/saas_proof.py`; `tests/test_saas_proof.py`; `FactoryLineCommands.saasVerify`; `FactoryLineCommands.saasStatus`; `FactoryLineCoreTest`; `docs/SAAS_PROOF.md`. |
| A slow or frozen-feeling IDE leads to guesswork and risky cache or setting changes. | **Guardian Core** is the first FactoryLine tab. It records at most 20 in-memory aggregate samples over a short local window: heap use, process CPU when available, indexing state, and EDT delay. It exposes an observation timeline and navigation-only review routes. | `FactoryLineGuardian.kt`; `FactoryLineCoreTest.guardian*`; `docs/JETBRAINS_GUARDIAN_CORE.md`. |
| A plugin can overstate performance or blame another plugin without evidence. | Guardian reports thresholds and transitions only. It never identifies root cause, ranks plugins, predicts duration, changes heap/caches/indexes/settings, or applies a fix. | Guardian assessment copy and tests; `docs/JETBRAINS_GUARDIAN_CORE.md`. |
| AI-authored or teammate code can look complete while its tests prove little. | Existing **Proof Review**, **Intent Ledger**, **Index Continuity**, and **Workspace Advisor** routes keep review facts separate from a human decision. Guardian opens their tabs; it does not run a CLI command from those routes. | `FactoryLineToolWindow.kt`, `FactoryLineActions.kt`, `plugin.xml`; route unit test in `FactoryLineCoreTest`. |
| A Junie or other AI-agent run can drift beyond the requested change or turn a red test green by weakening the test. | **AI Agent Proof Mission** copies a sealed, vendor-neutral working contract from one native Change List. It names the path boundary, forbids weakening a failing test merely to get green, requests exact changed paths/tests/failures/unknowns, and routes the returned workspace delta into independent Proof Review. FactoryLine neither starts nor controls Junie and does not read its chat. | `FactoryLineRepairSandbox.kt`; `FactoryLineCoreTest.aiAgentProofMissionKeepsJunieSupervisedAndVerificationIndependent`; `docs/REPAIR_SANDBOX.md`. |
| An agent and analyzer can both report green without proving the requested behavior. | **Analysis Evidence Adapter + Proof Handshake** binds one sealed Change List to recognized Qodana or SonarQube SARIF, intent evidence, and optional E2E evidence. Unknown, ambiguous, mismatched, or unsuccessful analysis fails closed; missing E2E remains explicitly unknown. | `factoryline/analysis_evidence.py`; `factoryline/jetbrains_handshake.py`; `tests/test_analysis_evidence.py`; `tests/test_jetbrains_handshake.py`. |
| A hard-won architectural decision can disappear from a handoff, then a later diff silently violates its stated proof obligations. | **Engineering Judgment** shows only repository-tracked, schema-bound Capsule state. A conventional human-declared Change Profile may label new change kinds and route attention deterministically; it is hash-bound and is never inferred from source. Separate workspace-confirmed local actions inspect Capsules or compile a Safety Case from one selected native Change List. | `FactoryLineJudgment.kt`, `FactoryLineCore.kt`, `FactoryLineActions.kt`, `FactoryLineCoreTest.judgment*`, `tests/test_judgment.py`, and `docs/ENGINEERING_JUDGMENT.md`. |
| Plugins execute with the IDE's privileges, so unconsented data handling or background changes are high risk. | Guardian retains bounded aggregate runtime values in-memory for the project session. It does not collect source content, file paths, plugin lists, credentials, or network data. CLI actions remain separately workspace-confirmed. | `FactoryLineIdeHealth.kt`, `FactoryLineGuardian.kt`, `FactoryLineActions.kt`, and `docs/JETBRAINS_GUARDIAN_CORE.md`. |
| A listing can declare incompatible or misleading metadata. | `marketplacePreflight` inspects the generated ZIP, not source alone: identity, patched version, `since-build`, platform/VCS modules, Guardian action registration, vendor contact, public URL, change notes, 40×40 SVG icons, archive size/path shape, and credential-shaped bundle entries. | `editors/intellij/build.gradle.kts`; run `./gradlew guardianReleaseGate`. |
| A local build can differ from the uploaded file or silently narrow compatibility. | The protected workflow seals one ZIP with SHA-256, tag, commit, and channel; its publish job consumes that artifact. Before publish, the same sealed ZIP is verified across IntelliJ IDEA, PyCharm, WebStorm, Rider, CLion, GoLand, RustRover, and DataGrip. | `.github/workflows/jetbrains-marketplace.yml`; `.github/workflows/intellij-plugin.yml`. |
| The candidate needs a repeatable local gate rather than an assertion that it "looks ready." | `guardianReleaseGate` runs unit tests, creates the ZIP, runs current-platform Plugin Verifier, validates package metadata, and requires a `Compatible` verifier verdict. | `editors/intellij/build.gradle.kts`; test report and Plugin Verifier output are generated under `editors/intellij/build/reports/`. |
| Open-source licensing, Marketplace EULA, vendor/trader, and pricing state can be confused. | The repository and plugin adapter are dual-licensed MIT/Apache-2.0. The optional paid plan is explicitly future-dated and inactive; the Marketplace EULA, Vendor Agreement acceptance, trader status, banking, and any paid onboarding remain account-side human gates. | `LICENSE`, `LICENSE-APACHE`, `LICENSE-MIT`, `editors/intellij/LICENSE`, `docs/JETBRAINS_MONETIZATION_2027.json`. |
| Marketplace publication or manual approval can be mistaken for a local build result. | The release workflow fails closed while a submitted Marketplace update is pending. A green package gate is a candidate receipt only; publication and approval require separate target-side read-back. | `scripts/jetbrains_marketplace_status.py`; `.github/workflows/jetbrains-marketplace.yml`. |

## Candidate boundary

FactoryLine 0.8.19 is a local, supervised JetBrains adapter. It does not
upload project source, store API keys, silently invoke a model, sign an
artifact, approve a change, merge, publish, deploy, or replace human release
authority. The Marketplace manual review team remains the authority for
approval timing and outcome.

**Fast reviewer path:** install the ZIP, open **View | Tool Windows |
FactoryLine**, confirm that **Verify SaaS journey** requests two project-local
JSON files and a second execution confirmation, then use **View SaaS status**
to inspect the local receipt. No provider account or network connection is
needed for this review path.

## Current test locations

The paths above describe the original release evidence. After test-module consolidation, current test locations are:

- `tests/test_jetbrains_handshake.py` → `tests/test_codex_metadata.py`
- `tests/test_judgment.py` → `tests/test_first_lap.py`

## Archived reviewer updates

These version-specific notes are retained here as release history, not current
Marketplace approval or runtime verification. Their original text is preserved.

# FactoryLine 0.8.21 — JetBrains reviewer summary

FactoryLine is a local, supervised evidence layer for JetBrains projects. It
does not replace Junie, GitHub Copilot, Qodana, SonarQube, App Store Connect,
or human review.

| Reviewer or developer concern | Shipped response | Evidence and boundary |
| --- | --- | --- |
| A coding agent and analyzer both say green, but the change escaped scope or its tests can no longer reject the intended failure. | **Proof Handshake** binds a sealed Change List, human-confirmed intent, supplied Qodana/SonarQube SARIF, and optional E2E receipt. Scope escape, unfamiliar/ambiguous SARIF, analyzer regression, hollow E2E, and missing evidence stay explicit. | `factoryline/analysis_evidence.py`, `factoryline/jetbrains_handshake.py`, `tests/test_analysis_evidence.py`, `tests/test_jetbrains_handshake.py`. It never starts an agent/analyzer or approves a change. |
| A team wants an MCP path without a secret or overwrite surprise. | **Junie MCP** and **Copilot proof agent** configuration is project-scoped, typed-confirmation gated, idempotent, and refuses conflicting existing files. | `factoryline/mcp_setup.py`, `tests/test_mcp_setup.py`. The client retains MCP approval and agent execution authority. |
| An iOS team only discovers missing Apple-review evidence after entering another queue. | **AppForge Mission Control** reads candidate-bound local receipt status for mission/design input, storyboard, App Review gate, strict quality audit, and submission dossier; it opens local Graph Ops for the full evidence chain. | `FactoryLineAppForge.kt`, `FactoryLineCore.kt`, `FactoryLineActions.kt`, `FactoryLineCoreTest`. It can surface preventable rework; it cannot access credentials, upload, start TestFlight, submit, or guarantee approval. |
| A plugin needs a repeatable, artifact-level release gate. | `guardianReleaseGate` runs tests, packages the ZIP, runs Plugin Verifier, and checks descriptor/icons/licenses/contact/archives from the generated artifact. | `editors/intellij/build.gradle.kts`; reports are retained below `build/reports/`. |

**Fast local path:** open **View | Tool Windows | FactoryLine | AppForge**, choose
**Refresh local AppForge status**, then inspect the bounded result. No Apple,
provider, or MCP account is needed. The plugin remains local and human-led.

## Current test locations

The paths above describe the original release evidence. After test-module consolidation, current test locations are:

- `tests/test_jetbrains_handshake.py` → `tests/test_codex_metadata.py`
- `tests/test_mcp_setup.py` → `tests/test_mcp.py`

# FactoryLine 0.8.22 — reviewer summary

- **User impact:** an externally orchestrated agent run can look complete while
  its workflow, handoffs, or resumed state drifted.
  **FactoryLine response:** Unified Graph Ops displays a verified Atomic Proof
  Adapter receipt bound to the current Oracle Contract.
  **Evidence:** `factoryline/atomic_proof_adapter.py`,
  `tests/test_atomic_proof_adapter.py`, and the `atomic-proof-panel` in
  `factoryline/graph_ops.html`.
- **Scope and source integrity:** the adapter rejects undeclared handoffs,
  capability or path scope escape, changed source bytes, topology drift, tool
  drift, and checkpoint drift.
  **Evidence:** stable `E_ATOMIC_*` failure codes and mutation-backed SpecLine
  contract `specs/atomic-proof-adapter-v1.md`.
- **IDE safety:** the JetBrains plugin remains confirmation-gated and the new
  view is read-only. It does not execute or resume the external workflow,
  change IDE settings, apply code, approve, merge, publish, deploy, or access
  credentials.
  **Evidence:** plugin description, Graph Ops authority map, MCP/WebMCP
  read-only declarations, and package tests.
- **Compatibility and approval:** compatibility, packaging, signing, and
  Marketplace submission are rechecked by the protected JDK 21 release gate.
  JetBrains moderation timing and approval remain external decisions.
