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
