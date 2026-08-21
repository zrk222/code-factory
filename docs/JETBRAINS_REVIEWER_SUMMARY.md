# FactoryLine 0.8.14 — JetBrains reviewer summary

This is a concise map from common IDE and Marketplace review concerns to the
candidate's shipped behavior and local evidence. It describes the candidate;
it is not a claim of Marketplace approval or a diagnosis of an IDE.

| Review concern / user impact | FactoryLine response | Proof or reference |
| --- | --- | --- |
| A slow or frozen-feeling IDE leads to guesswork and risky cache or setting changes. | **Guardian Core** is the first FactoryLine tab. It records at most 20 in-memory aggregate samples over a short local window: heap use, process CPU when available, indexing state, and EDT delay. It exposes an observation timeline and navigation-only review routes. | `FactoryLineGuardian.kt`; `FactoryLineCoreTest.guardian*`; `docs/JETBRAINS_GUARDIAN_CORE.md`. |
| A plugin can overstate performance or blame another plugin without evidence. | Guardian reports thresholds and transitions only. It never identifies root cause, ranks plugins, predicts duration, changes heap/caches/indexes/settings, or applies a fix. | Guardian assessment copy and tests; `docs/JETBRAINS_GUARDIAN_CORE.md`. |
| AI-authored or teammate code can look complete while its tests prove little. | Existing **Proof Review**, **Intent Ledger**, **Index Continuity**, and **Workspace Advisor** routes keep review facts separate from a human decision. Guardian opens their tabs; it does not run a CLI command from those routes. | `FactoryLineToolWindow.kt`, `FactoryLineActions.kt`, `plugin.xml`; route unit test in `FactoryLineCoreTest`. |
| Plugins execute with the IDE's privileges, so unconsented data handling or background changes are high risk. | Guardian retains bounded aggregate runtime values in-memory for the project session. It does not collect source content, file paths, plugin lists, credentials, or network data. CLI actions remain separately workspace-confirmed. | `FactoryLineIdeHealth.kt`, `FactoryLineGuardian.kt`, `FactoryLineActions.kt`, and `docs/JETBRAINS_GUARDIAN_CORE.md`. |
| A listing can declare incompatible or misleading metadata. | `marketplacePreflight` inspects the generated ZIP, not source alone: identity, patched version, `since-build`, platform/VCS modules, Guardian action registration, vendor contact, public URL, change notes, 40×40 SVG icons, archive size/path shape, and credential-shaped bundle entries. | `editors/intellij/build.gradle.kts`; run `./gradlew guardianReleaseGate`. |
| A local build can differ from the uploaded file or silently narrow compatibility. | The protected workflow seals one ZIP with SHA-256, tag, commit, and channel; its publish job consumes that artifact. Before publish, the same sealed ZIP is verified across IntelliJ IDEA, PyCharm, WebStorm, Rider, CLion, GoLand, RustRover, and DataGrip. | `.github/workflows/jetbrains-marketplace.yml`; `.github/workflows/intellij-plugin.yml`. |
| The candidate needs a repeatable local gate rather than an assertion that it "looks ready." | `guardianReleaseGate` runs unit tests, creates the ZIP, runs current-platform Plugin Verifier, validates package metadata, and requires a `Compatible` verifier verdict. | `editors/intellij/build.gradle.kts`; test report and Plugin Verifier output are generated under `editors/intellij/build/reports/`. |
| Open-source licensing, Marketplace EULA, vendor/trader, and pricing state can be confused. | The repository and plugin adapter are dual-licensed MIT/Apache-2.0. The optional paid plan is explicitly future-dated and inactive; the Marketplace EULA, Vendor Agreement acceptance, trader status, banking, and any paid onboarding remain account-side human gates. | `LICENSE`, `LICENSE-APACHE`, `LICENSE-MIT`, `editors/intellij/LICENSE`, `docs/JETBRAINS_MONETIZATION_2027.json`. |
| Marketplace publication or manual approval can be mistaken for a local build result. | The release workflow fails closed while a submitted Marketplace update is pending. A green package gate is a candidate receipt only; publication and approval require separate target-side read-back. | `scripts/jetbrains_marketplace_status.py`; `.github/workflows/jetbrains-marketplace.yml`. |

## Candidate boundary

FactoryLine 0.8.14 is a local, supervised JetBrains adapter. It does not
upload project source, store API keys, silently invoke a model, sign an
artifact, approve a change, merge, publish, deploy, or replace human release
authority. The Marketplace manual review team remains the authority for
approval timing and outcome.
